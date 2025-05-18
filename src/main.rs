#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod file_handler;
use eframe::{App, NativeOptions, egui};
use egui_inbox::UiInbox;
use file_handler::{process_item, DataSource};
use rand::{Rng, distr::Alphanumeric};
use rayon::prelude::*;
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    process::Command as StdCommand,
    thread,
};
use thiserror::Error;
use walkdir::WalkDir;

// --- Error Handling ---

#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O Error")]
    Io(#[from] std::io::Error),
    #[error("ZIP Processing Error")]
    Zip(#[from] zip::result::ZipError),
    #[error("Json ser Error")]
    Json(#[from] serde_json::Error),
    #[error("WalkDir run Error")]
    WalkDir(#[from] walkdir::Error),
    #[error("Configuration Error: {0}")]
    ConfigError(String),
    #[error("Analysis Error: {0}")]
    AnalysisError(String),
    #[error("Command Execution Error: {0}")]
    CommandError(String),
    #[error("Other Error: {0}")]
    OtherError(String),
}

type Result<T> = std::result::Result<T, AppError>;

// --- Configuration ---
#[derive(Deserialize, Serialize)]
struct CommandConfig {
    description: String,
    executable: String,
    args: Vec<String>,
}

fn load_commands() -> Result<Vec<CommandConfig>> {
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| AppError::ConfigError("Failed to get executable directory".to_string()))?;
    let config_path = exe_dir.join("commands.json");

    if !config_path.exists() {
        // Create a default commands.json if it doesn't exist
        let default_commands = vec![
            CommandConfig {
                description: "Use klogg (Windows)".to_string(),
                executable: "klogg.exe".to_string(),
                args: vec!["{file}".to_string()],
            },            
            CommandConfig {
                description: "Use Notepad (Windows)".to_string(),
                executable: "notepad.exe".to_string(),
                args: vec!["{file}".to_string()],
            },
            CommandConfig {
                description: "Use TextEdit (macOS)".to_string(),
                executable: "open".to_string(),
                args: vec!["{file}".to_string()],
            },
            CommandConfig {
                description: "Use gedit (Linux)".to_string(),
                executable: "gedit".to_string(),
                args: vec!["{file}".to_string()],
            },
        ];
        let json_string = serde_json::to_string_pretty(&default_commands)?;
        fs::write(&config_path, json_string)?;
        return Ok(default_commands);
    }

    let file_content = fs::read_to_string(config_path)?;
    let commands: Vec<CommandConfig> = serde_json::from_str(&file_content)?;
    Ok(commands)
}

// --- Analysis Logic ---
#[derive(Debug)]
enum AnalysisUpdate {
    FileProcessed(String), // Name of the file processed
    Error(String),
    Completed(PathBuf, u128), // Path to the generated log file
}

fn process_dir(input_path: &PathBuf, all_lines: &mut Vec<String>, sender: egui_inbox::UiInboxSender<AnalysisUpdate>,) -> anyhow::Result<()> {
    for entry in WalkDir::new(input_path)
        .into_iter()
        .filter_map(walkdir::Result::ok)
    {
        if entry.path() == input_path.as_path() {
            continue;
        }
        if entry.file_type().is_file() {
            process_item(DataSource::Path(entry.path()), &entry.path().file_name().unwrap_or_default().to_string_lossy(), all_lines, 0, sender.clone())?;
        } else {
            process_dir(&PathBuf::from(entry.path()), all_lines, sender.clone())?;
        }
    }
    Ok(())
}


fn process_input_path(
    input_path: PathBuf,
    sender: egui_inbox::UiInboxSender<AnalysisUpdate>,
    sorted: bool,
) -> Result<PathBuf> {
    let mut all_lines: Vec<String> = Vec::new();

    if input_path.is_dir() {
        process_dir(&input_path, &mut all_lines, sender).map_err(|e| AppError::OtherError(format!("{:?}", e)))?;
    } else {
        process_item(DataSource::Path(input_path.as_path()), &input_path.as_path().file_name().unwrap_or_default().to_string_lossy(), &mut all_lines, 0, sender).map_err(|e| AppError::OtherError(format!("{:?}", e)))?;
    }
    if sorted {
        all_lines.par_sort_unstable();
    }
    // Save to log file
    let temp_dir = std::env::temp_dir();
    let log_rt_dir = temp_dir.join("log_rt");
    fs::create_dir_all(&log_rt_dir)?;

    let original_name = input_path.file_stem().unwrap_or_default().to_string_lossy();
    let random_suffix: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    let log_file_name = format!("{}_{}.log", original_name, random_suffix);
    let log_file_path = log_rt_dir.join(log_file_name);

    let mut output_file = BufWriter::new(fs::File::create(&log_file_path)?);
    for line in all_lines {
        writeln!(output_file, "{}", line)?;
    }
    output_file.flush()?;

    Ok(log_file_path)
}

// --- egui App ---
struct MyApp {
    path_to_analyze_str: String, // For text input field
    dropped_file_path: Option<PathBuf>,
    analysis_in_progress: bool,
    progress: f32,
    status_message: String,
    commands: Vec<CommandConfig>,
    selected_command_index: usize,
    log_output_dir: PathBuf,
    analysis_inbox: UiInbox<AnalysisUpdate>, // Using UiInbox
    analysis_thread_join_handle: Option<thread::JoinHandle<()>>,
    sorted: bool,
}

impl Default for MyApp {
    fn default() -> Self {
        let log_output_dir = std::env::temp_dir().join("log_rt");
        if !log_output_dir.exists() {
            let _ = fs::create_dir_all(&log_output_dir);
        }
        let commands = load_commands().unwrap_or_else(|e| {
            eprintln!("Failed to load commands: {}", e);
            vec![CommandConfig {
                // Fallback default
                description: "Error: commands.json missing/invalid".to_string(),
                executable: "".to_string(),
                args: vec![],
            }]
        });

        Self {
            path_to_analyze_str: "".to_string(),
            dropped_file_path: None,
            analysis_in_progress: false,
            progress: 0.0,
            status_message: "Ready.".to_string(),
            commands,
            selected_command_index: 0,
            log_output_dir,
            analysis_inbox: UiInbox::new(),
            analysis_thread_join_handle: None,
            sorted: true
        }
    }
}

impl App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle updates from analysis thread
        if let Some(update) = self.analysis_inbox.read(ctx).last() {
            match update {
                AnalysisUpdate::FileProcessed(name) => {
                    self.status_message = format!("Processing: {}", name);
                }
                AnalysisUpdate::Error(e) => {
                    self.status_message = format!("Error: {}", e);
                    self.analysis_in_progress = false;
                    if let Some(handle) = self.analysis_thread_join_handle.take() {
                        let _ = handle.join();
                    }
                }
                AnalysisUpdate::Completed(log_path, use_time) => {
                    self.status_message =
                        format!("Analysis complete {} ms! Log saved to: {}", use_time, log_path.display());
                    self.analysis_in_progress = false;
                    if let Some(handle) = self.analysis_thread_join_handle.take() {
                        let _ = handle.join();
                    }
                    // Automatically open the file
                    if !self.commands.is_empty()
                        && self.selected_command_index < self.commands.len()
                    {
                        let cmd_config = &self.commands[self.selected_command_index];
                        if !cmd_config.executable.is_empty() {
                            let log_path_str = log_path.to_string_lossy();
                            let processed_args: Vec<String> = cmd_config
                                .args
                                .iter()
                                .map(|arg| arg.replace("{file}", &log_path_str))
                                .collect();
                            match StdCommand::new(&cmd_config.executable)
                                .args(&processed_args)
                                .spawn()
                            {
                                Ok(_) => self.status_message.push_str(&format!(
                                    " | Opened with: {}",
                                    cmd_config.description
                                )),
                                Err(e) => self.status_message.push_str(&format!(
                                    " | Failed to open with {}: {}",
                                    cmd_config.description, e
                                )),
                            }
                        }
                    }
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Log Analyzer");
            ui.separator();

            // File/Folder Selection
            ui.horizontal(|ui| {
                ui.label("Path to analyze:");
                ui.text_edit_singleline(&mut self.path_to_analyze_str);
                if ui.button("Browse...").clicked() {
                    if let Some(path) = FileDialog::new().pick_folder() {
                        // Or.pick_file() for archives
                        self.path_to_analyze_str = path.to_string_lossy().into_owned();
                        self.dropped_file_path = None; // Clear dropped file if browse is used
                    } else if let Some(path) = FileDialog::new()
                        .add_filter("ZIP archives", &["zip"])
                        .pick_file()
                    {
                        self.path_to_analyze_str = path.to_string_lossy().into_owned();
                        self.dropped_file_path = None;
                    }
                }
            });

            // Drag and Drop Info
            if self.dropped_file_path.is_some() {
                ui.label(format!(
                    "Dropped file: {}",
                    self.dropped_file_path.as_ref().unwrap().display()
                ));
            } else {
                ui.label("Or drag a compressed file (.zip) or folder onto this window.");
            }

            // Detect dropped files
            if !ctx.input(|i| i.raw.hovered_files.is_empty()) {
                ui.centered_and_justified(|ui| {
                    ui.label("Drop file here!");
                });
            }
            if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
                if let Some(file) = ctx.input(|i| i.raw.dropped_files.first().cloned()) {
                    if let Some(path) = file.path {
                        // path is Option<PathBuf>
                        self.dropped_file_path = Some(path.clone());
                        self.path_to_analyze_str = path.to_string_lossy().into_owned(); // Also update text field
                    } else {
                        self.status_message =
                            "Dropped item has no path (e.g., web drop).".to_string();
                    }
                }
            }

            // Command Selection
            ui.horizontal(|ui| {
                ui.label("Open log with:");
                let selected_command_text = if !self.commands.is_empty()
                    && self.selected_command_index < self.commands.len()
                {
                    self.commands[self.selected_command_index]
                        .description
                        .clone()
                } else {
                    "No commands available".to_string()
                };
                egui::ComboBox::from_id_salt("command_select")
                    .selected_text(selected_command_text)
                    .show_ui(ui, |ui| {
                        for (idx, cmd) in self.commands.iter().enumerate() {
                            ui.selectable_value(
                                &mut self.selected_command_index,
                                idx,
                                &cmd.description,
                            );
                        }
                    });
            });
            ui.separator();

            // Action Buttons
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.analysis_in_progress,
                        egui::Button::new("Start Analysis"),
                    )
                    .clicked()
                {
                    let path_to_use_str = self.path_to_analyze_str.trim();
                    if !path_to_use_str.is_empty() {
                        let path_to_use = PathBuf::from(path_to_use_str);
                        if path_to_use.exists() {
                            self.analysis_in_progress = true;
                            self.progress = 0.0;
                            self.status_message = "Starting analysis...".to_string();

                            let analysis_path = path_to_use.clone();
                            let sender = self.analysis_inbox.sender();
                            let sorted = self.sorted;
                            self.analysis_thread_join_handle = Some(thread::spawn(move || {
                                let begin_time = std::time::Instant::now();
                                match process_input_path(analysis_path, sender.clone(), sorted) {
                                    Ok(log_file_path) => {
                                        let end_time = std::time::Instant::now();
                                        let _ =
                                            sender.send(AnalysisUpdate::Completed(log_file_path, (end_time - begin_time).as_millis()));
                                    }
                                    Err(e) => {
                                        let _ = sender.send(AnalysisUpdate::Error(format!(
                                            "Analysis failed: {}",
                                            e
                                        )));
                                    }
                                }
                            }));
                        } else {
                            self.status_message =
                                "Error: Specified path does not exist.".to_string();
                        }
                    } else {
                        self.status_message = "Error: No path specified for analysis.".to_string();
                    }
                }

                if ui.button("Clear Generated Logs").clicked() {
                    if self.log_output_dir.exists() {
                        match fs::remove_dir_all(&self.log_output_dir) {
                            Ok(_) => {
                                if fs::create_dir_all(&self.log_output_dir).is_ok() {
                                    self.status_message =
                                        "Log directory cleared and recreated.".to_string();
                                } else {
                                    self.status_message =
                                        "Log directory cleared, but failed to recreate."
                                            .to_string();
                                }
                            }
                            Err(e) => {
                                self.status_message =
                                    format!("Failed to clear log directory: {}", e)
                            }
                        }
                    } else {
                        self.status_message = "Log directory does not exist.".to_string();
                    }
                }

                if ui.radio(self.sorted, "sort").clicked() {
                    self.sorted = !self.sorted;
                }
            });
            ui.separator();

            // Progress and Status
            if self.analysis_in_progress {
                ui.add(
                    egui::ProgressBar::new(self.progress)
                        .show_percentage()
                        .animate(true),
                );
            }
            ui.label(&self.status_message);
        });

        // Request repaint if there are pending messages or animation
        if self.analysis_in_progress {
            ctx.request_repaint();
        }
    }
}

fn main() -> eframe::Result<()> {
    let native_options = NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([600.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Rust Log Analyzer",
        native_options,
        Box::new(|_cc| Ok(Box::new(MyApp::default()))),
    )
}
