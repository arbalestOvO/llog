use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

// 依赖项 (需在 Cargo.toml 中声明)
use anyhow::{anyhow, Context, Result};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use sevenz_rust2::{Password, SevenZReader};
use tar::Archive as TarArchive;
use xz2::read::XzDecoder;
use zip::ZipArchive;

use crate::AnalysisUpdate;

pub enum FileType {
    SevenZ,
    Xz,
    Bzip2,
    Gzip,
    Tar,
    Zip,
    PlainText,
    Unknown,
}

pub enum DataSource<'a> {
    Path(&'a Path),
    Bytes(&'a [u8]),
}

fn identify_file_type(data_source: &DataSource, item_name: &str) -> Result<FileType> {
    let mut buffer = [0u8; 300]; // 读取足够字节用于魔数判断，例如 TAR 的 ustar 在 257 偏移

    let bytes_read: &[u8] = match data_source {
        DataSource::Path(path) => {
            let mut file = fs::File::open(path)
               .with_context(|| format!("Failed to open file for type identification: {}", path.display()))?;
            let n = file.read(&mut buffer)
               .with_context(|| format!("Failed to read from file for type identification: {}", path.display()))?;
            &buffer[..n]
        }
        DataSource::Bytes(data) => {
            let len = std::cmp::min(data.len(), buffer.len());
            &data[..len]
        }
    };

    if bytes_read.is_empty() { // 空文件或空数据
        if item_name.ends_with(".txt") || item_name.ends_with(".md") || item_name.ends_with(".log") {
             return Ok(FileType::PlainText); // 根据后缀名猜测
        }
        return Ok(FileType::Unknown);
    }
    
    // 使用 infer crate 进行类型推断
    if let Some(kind) = infer::get(bytes_read) {
        match kind.extension() {
            "7z" => return Ok(FileType::SevenZ),
            "xz" => return Ok(FileType::Xz),
            "bz2" => return Ok(FileType::Bzip2),
            "gz" => return Ok(FileType::Gzip),
            "tar" => return Ok(FileType::Tar),
            "zip" => return Ok(FileType::Zip),
            "txt" | "md" | "json" | "xml" | "html" | "csv" | "rs" | "py" | "log" => return Ok(FileType::PlainText),
            _ => {} // 继续尝试后缀名或其他逻辑
        }
    }

    // 基于后缀名的后备判断 (infer 可能已处理大部分情况)
    let lower_item_name = item_name.to_lowercase();
    if lower_item_name.ends_with(".7z") { Ok(FileType::SevenZ) }
    else if lower_item_name.ends_with(".xz") { Ok(FileType::Xz) }
    else if lower_item_name.ends_with(".bz2") { Ok(FileType::Bzip2) }
    else if lower_item_name.ends_with(".gz") || lower_item_name.ends_with(".tgz") { Ok(FileType::Gzip) }
    else if lower_item_name.ends_with(".tar") { Ok(FileType::Tar) } // tar.gz 等会被 Gzip 先处理
    else if lower_item_name.ends_with(".zip") { Ok(FileType::Zip) }
    else if lower_item_name.ends_with(".txt") || lower_item_name.ends_with(".md") ||
              lower_item_name.ends_with(".rs") || lower_item_name.ends_with(".toml") ||
              lower_item_name.ends_with(".json") || lower_item_name.ends_with(".xml") ||
              lower_item_name.ends_with(".log") { Ok(FileType::PlainText) }
    else { Ok(FileType::Unknown) }
}


pub fn process_item(
    data_source: DataSource,
    item_name: &str,
    all_contents: &mut Vec<String>,
    depth: usize, // 用于防止无限递归和调试
    sender: egui_inbox::UiInboxSender<AnalysisUpdate>, 
) -> Result<()> {
    if depth > 10 { // 设定一个最大递归深度
        eprintln!("Max recursion depth reached for item: {}", item_name);
        return Ok(());
    }
    // println!("{}{}", "  ".repeat(depth), item_name);


    let file_type = identify_file_type(&data_source, item_name)
       .with_context(|| format!("Failed to identify file type for {}", item_name))?;
    
    // println!("{}{:?}", "  ".repeat(depth+1), file_type);

    sender.send(AnalysisUpdate::FileProcessed(
                    item_name.to_owned()
                )).map_err(|e| anyhow!(format!("{:?}", e)))?;
    let item_data: Vec<u8> = match data_source {
        DataSource::Path(path) => {
            fs::read(path).with_context(|| format!("Failed to read file content from path: {}", path.display()))?
        }
        DataSource::Bytes(bytes) => {
            bytes.to_vec()
        }
    };

    match file_type {
        FileType::PlainText => {
            let content = String::from_utf8_lossy(&item_data);
            all_contents.push(content.into_owned());
        }
        FileType::SevenZ => {
            handle_sevenz(&item_data, item_name, all_contents, depth + 1, sender)
               .with_context(|| format!("Error handling 7z: {}", item_name))?;
        }
        FileType::Zip => {
            handle_zip(&item_data, item_name, all_contents, depth + 1, sender)
               .with_context(|| format!("Error handling zip: {}", item_name))?;
        }
        FileType::Tar => {
            handle_tar(&item_data, item_name, all_contents, depth + 1, sender)
               .with_context(|| format!("Error handling tar: {}", item_name))?;
        }
        FileType::Gzip => {
            handle_gzip(&item_data, item_name, all_contents, depth + 1, sender)
               .with_context(|| format!("Error handling gzip: {}", item_name))?;
        }
        FileType::Xz => {
            handle_xz(&item_data, item_name, all_contents, depth + 1, sender)
               .with_context(|| format!("Error handling xz: {}", item_name))?;
        }
        FileType::Bzip2 => {
            handle_bzip2(&item_data, item_name, all_contents, depth + 1, sender)
               .with_context(|| format!("Error handling bzip2: {}", item_name))?;
        }
        FileType::Unknown => {
            // eprintln!("Unknown file type for: {}, attempting to read as text.", item_name);
            // 尝试作为文本读取，如果不是文本，from_utf8_lossy 会处理
            let content = String::from_utf8_lossy(&item_data);
            if!content.chars().any(|c| c == '\u{FFFD}') || content.len() < 256 { // 简单 heuristic
                 // println!("{}  Reading as plain text (unknown type): {}", "  ".repeat(depth+1), item_name);
                 all_contents.push(content.into_owned());
            } else {
                 // println!("{}  Skipping binary-like unknown file: {}", "  ".repeat(depth+1), item_name);
            }
        }
    }
    Ok(())
}

fn handle_sevenz(archive_data: &[u8], archive_name: &str, all_contents: &mut Vec<String>, depth: usize, sender: egui_inbox::UiInboxSender<AnalysisUpdate>,) -> Result<()> {
    let cursor = Cursor::new(archive_data);
    let mut sz_reader = SevenZReader::new(cursor, Password::empty())
       .map_err(|e| anyhow::anyhow!("Failed to create SevenZReader for {}: {:?}", archive_name, e))?;

    sz_reader.for_each_entries(|entry, reader| {
        if entry.is_directory {
            return Ok(true);
        }
        let mut buffer = vec![];
        reader.read_to_end(&mut buffer)?;
        process_item(DataSource::Bytes(&buffer), entry.name(), all_contents, depth + 1, sender.clone()).map_err(|e| sevenz_rust2::Error::UnsupportedCompressionMethod(format!("{:?}", e)))?;
        Ok(true)
    }).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

fn handle_zip(archive_data: &[u8], archive_name: &str, all_contents: &mut Vec<String>, depth: usize, sender: egui_inbox::UiInboxSender<AnalysisUpdate>,) -> Result<()> {
    let cursor = Cursor::new(archive_data);
    let mut archive = ZipArchive::new(cursor)
       .with_context(|| format!("Failed to open ZIP archive: {}", archive_name))?;

    for i in 0..archive.len() {
        let mut file_entry = archive.by_index(i)
           .with_context(|| format!("Failed to get entry {} from ZIP: {}", i, archive_name))?;
        
        if file_entry.is_dir() {
            continue;
        }
        let entry_name = file_entry.name().to_string(); // Clone name as file_entry is consumed
        // println!("{}  Extracting from zip: {}", "  ".repeat(depth), entry_name);


        let mut content_bytes = Vec::new();
        file_entry.read_to_end(&mut content_bytes)
           .with_context(|| format!("Failed to read content of {} from ZIP: {}", entry_name, archive_name))?;
        
        process_item(DataSource::Bytes(&content_bytes), &entry_name, all_contents, depth + 1, sender.clone())?;
    }
    Ok(())
}

fn handle_tar(archive_data: &[u8], archive_name: &str, all_contents: &mut Vec<String>, depth: usize, sender: egui_inbox::UiInboxSender<AnalysisUpdate>,) -> Result<()> {
    let cursor = Cursor::new(archive_data);
    let mut archive = TarArchive::new(cursor); // TAR 通常不压缩，若有压缩，外层 Gzip/Bz2 已处理

    for entry_result in archive.entries().with_context(|| format!("Failed to iterate TAR entries: {}", archive_name))? {
        let mut entry = entry_result.with_context(|| format!("Invalid entry in TAR: {}", archive_name))?;
        
        if entry.header().entry_type().is_file() {
            let entry_path = entry.path()?.to_string_lossy().to_string();
            // println!("{}  Extracting from tar: {}", "  ".repeat(depth), entry_path);

            let mut content_bytes = Vec::new();
            entry.read_to_end(&mut content_bytes)
               .with_context(|| format!("Failed to read content of {} from TAR: {}", entry_path, archive_name))?;

            process_item(DataSource::Bytes(&content_bytes), &entry_path, all_contents, depth + 1, sender.clone())?;
        }
    }
    Ok(())
}

fn handle_gzip(archive_data: &[u8], archive_name: &str, all_contents: &mut Vec<String>, depth: usize, sender: egui_inbox::UiInboxSender<AnalysisUpdate>,) -> Result<()> {
    let cursor = Cursor::new(archive_data);
    let mut decoder = GzDecoder::new(cursor);
    let mut decompressed_bytes = Vec::new();
    decoder.read_to_end(&mut decompressed_bytes)
       .with_context(|| format!("Failed to decompress GZIP stream: {}", archive_name))?;
    
    let new_item_name = archive_name.strip_suffix(".gz").unwrap_or(archive_name);
    let new_item_name_tgz = new_item_name.strip_suffix(".tgz").unwrap_or(new_item_name);
    let final_name = if new_item_name_tgz.ends_with(".tar") {
        new_item_name_tgz
    } else if !new_item_name_tgz.contains('.') && archive_name.to_lowercase().contains(".tar.gz") { // Heuristic for.tar.gz where only.gz is stripped
        &format!("{}.tar", new_item_name_tgz)
    } else {
        new_item_name_tgz
    };

    process_item(DataSource::Bytes(&decompressed_bytes), final_name, all_contents, depth + 1, sender.clone())?;
    Ok(())
}

fn handle_xz(archive_data: &[u8], archive_name: &str, all_contents: &mut Vec<String>, depth: usize, sender: egui_inbox::UiInboxSender<AnalysisUpdate>,) -> Result<()> {
    let cursor = Cursor::new(archive_data);
    let mut decoder = XzDecoder::new(cursor);
    let mut decompressed_bytes = Vec::new();
    decoder.read_to_end(&mut decompressed_bytes)
       .with_context(|| format!("Failed to decompress XZ stream: {}", archive_name))?;

    let new_item_name = archive_name.strip_suffix(".xz").unwrap_or(archive_name);
    process_item(DataSource::Bytes(&decompressed_bytes), new_item_name, all_contents, depth + 1, sender.clone())?;
    Ok(())
}

fn handle_bzip2(archive_data: &[u8], archive_name: &str, all_contents: &mut Vec<String>, depth: usize, sender: egui_inbox::UiInboxSender<AnalysisUpdate>,) -> Result<()> {
    let cursor = Cursor::new(archive_data);
    let mut decoder = BzDecoder::new(cursor);
    let mut decompressed_bytes = Vec::new();
    decoder.read_to_end(&mut decompressed_bytes)
       .with_context(|| format!("Failed to decompress BZIP2 stream: {}", archive_name))?;

    let new_item_name = archive_name.strip_suffix(".bz2").unwrap_or(archive_name);
    process_item(DataSource::Bytes(&decompressed_bytes), new_item_name, all_contents, depth + 1, sender.clone())?;
    Ok(())
}