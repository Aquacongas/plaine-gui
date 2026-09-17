#![forbid(unsafe_code)]

mod chain_history;
mod chain_index;
mod prefs;
mod rpc;
mod wallet;

use std::time::{Duration, Instant};

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Pla(i)n[e] Wallet")
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Pla(i)n[e] Wallet",
        options,
        Box::new(|cc| {
            configure_style(&cc.egui_ctx);
            Ok(Box::new(PlaineApp::new()))
        }),
    )
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::light();

    visuals.panel_fill = egui::Color32::WHITE;
    visuals.window_fill = egui::Color32::WHITE;
    visuals.extreme_bg_color = egui::Color32::WHITE;

    visuals.widgets.inactive.bg_fill = egui::Color32::WHITE;
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);

    visuals.widgets.hovered.bg_fill = egui::Color32::BLACK;
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::WHITE);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);

    visuals.widgets.active.bg_fill = egui::Color32::BLACK;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::WHITE);

    visuals.selection.bg_fill = egui::Color32::BLACK;
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, egui::Color32::WHITE);

    ctx.set_visuals(visuals);
}

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Wallet,
    Send,
    Receive,
    History,
    Settings,
}

enum PendingOverwrite {
    Create {
        path: std::path::PathBuf,
        password: String,
    },
    Import {
        path: std::path::PathBuf,
        backup: String,
        password: String,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum FeeLevel {
    Economy,
    Normal,
    Priority,
}

struct PendingSend {
    raw_hex: String,
    to: String,
    amount_mile: u128,
    fee_mile: u128,
    nonce: u64,
}

struct PlaineApp {
    screen: Screen,

    embedded_node: Option<plaine_noded::EmbeddedNode>,
    chain: Option<rpc::ChainInfo>,
    node_error: Option<String>,

    wallet: Option<wallet::LoadedWallet>,
    account: Option<rpc::AccountInfo>,
    wallet_error: Option<String>,

    wallet_unlocked: bool,
    wallet_session: Option<plaine_wallet::secret::SecretBytes>,
    unlock_password: String,
    show_unlock_dialog: bool,

    last_rpc_update: Instant,
    last_chain_scan: Instant,

    show_create_dialog: bool,
    show_import_dialog: bool,

    create_password: String,
    create_password2: String,

    import_backup: String,
    import_password: String,

    pending_backup: Option<String>,
    pending_overwrite: Option<PendingOverwrite>,

    send_to: String,
    send_amount: String,
    send_password: String,
    send_fee_level: FeeLevel,

    pending_send: Option<PendingSend>,
    send_error: Option<String>,
    send_result: Option<String>,

    show_existing_backup_dialog: bool,
    backup_password: String,
    revealed_backup: Option<String>,

    show_passphrase_dialog: bool,
    old_wallet_password: String,
    new_wallet_password: String,
    new_wallet_password2: String,
    remove_wallet_encryption: bool,

    security_message: Option<String>,

    security_busy: bool,
    security_rx: Option<std::sync::mpsc::Receiver<Result<wallet::LoadedWallet, String>>>,

    sent_history: Vec<prefs::SentTx>,
    mempool_txids: std::collections::HashSet<String>,

    chain_history: Vec<chain_history::ChainTx>,

    chain_scan_busy: bool,

    chain_scan_rx: Option<std::sync::mpsc::Receiver<Result<chain_index::ChainState, String>>>,

    chain_scan_error: Option<String>,
}

impl PlaineApp {
    fn new() -> Self {
        let embedded_node = match plaine_noded::EmbeddedNode::start_default() {
            Ok(node) => Some(node),
            Err(_) => None,
        };

        if let Some(node) = embedded_node.as_ref() {
            let _ = rpc::install_direct_api(node.direct_api());
        }

        let mut app = Self {
            screen: Screen::Wallet,

            embedded_node,

            chain: None,
            node_error: None,

            wallet: None,
            account: None,
            wallet_error: None,

            wallet_unlocked: false,
            wallet_session: None,
            unlock_password: String::new(),
            show_unlock_dialog: false,

            last_rpc_update: Instant::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap_or_else(Instant::now),

            last_chain_scan: Instant::now()
                .checked_sub(Duration::from_secs(60))
                .unwrap_or_else(Instant::now),

            show_create_dialog: false,
            show_import_dialog: false,

            create_password: String::new(),
            create_password2: String::new(),

            import_backup: String::new(),
            import_password: String::new(),

            pending_backup: None,
            pending_overwrite: None,

            send_to: String::new(),
            send_amount: String::new(),
            send_password: String::new(),
            send_fee_level: FeeLevel::Normal,

            pending_send: None,
            send_error: None,
            send_result: None,

            show_existing_backup_dialog: false,
            backup_password: String::new(),
            revealed_backup: None,

            show_passphrase_dialog: false,
            old_wallet_password: String::new(),
            new_wallet_password: String::new(),
            new_wallet_password2: String::new(),
            remove_wallet_encryption: false,

            security_message: None,

            security_busy: false,
            security_rx: None,

            sent_history: Vec::new(),
            mempool_txids: std::collections::HashSet::new(),

            chain_history: Vec::new(),

            chain_scan_busy: false,
            chain_scan_rx: None,
            chain_scan_error: None,
        };

        std::thread::sleep(Duration::from_millis(150));

        app.refresh_node();

        if let Some(path) = prefs::load_last_wallet() {
            if let Err(e) = app.open_wallet_path(&path) {
                app.wallet_error = Some(format!("cannot open last wallet: {e}"));
            }
        }

        app
    }

    fn refresh_node(&mut self) {
        match rpc::chain_get_info() {
            Ok(info) => {
                self.chain = Some(info);
                self.node_error = None;
            }

            Err(e) => {
                self.chain = None;
                self.node_error = Some(e);
            }
        }

        self.refresh_account();
        self.refresh_mempool();

        self.last_rpc_update = Instant::now();
    }

    fn refresh_account(&mut self) {
        let Some(w) = &self.wallet else {
            self.account = None;
            return;
        };

        match rpc::account_get(&w.address) {
            Ok(account) => {
                self.account = Some(account);
            }

            Err(e) => {
                self.account = None;
                self.wallet_error = Some(e);
            }
        }
    }

    fn load_chain_history(&mut self) {
        let Some(w) = self.wallet.as_ref() else {
            self.chain_history.clear();
            return;
        };

        let state = chain_index::load(&w.address);

        self.chain_history = state.txs;
    }

    fn start_chain_scan(&mut self) {
        if self.chain_scan_busy {
            return;
        }

        let Some(w) = self.wallet.as_ref() else {
            return;
        };

        let Some(node) = self.embedded_node.as_ref() else {
            return;
        };

        let reader = node.history_reader();
        let address = w.address.clone();
        let target = reader.tip_height();
        let start = reader.prune_floor();

        let (tx, rx) = std::sync::mpsc::channel();

        self.chain_scan_busy = true;
        self.last_chain_scan = Instant::now();
        self.chain_scan_rx = Some(rx);
        self.chain_scan_error = None;

        std::thread::spawn(move || {
            let result = chain_index::scan_to_height(reader, &address, target, start);

            let _ = tx.send(result);
        });
    }

    fn poll_chain_scan(&mut self) {
        let Some(rx) = self.chain_scan_rx.as_ref() else {
            return;
        };

        match rx.try_recv() {
            Ok(result) => {
                self.chain_scan_busy = false;
                self.chain_scan_rx = None;

                match result {
                    Ok(state) => {
                        self.chain_history = state.txs;

                        self.chain_scan_error = None;
                    }

                    Err(e) => {
                        self.chain_scan_error = Some(e);
                    }
                }
            }

            Err(std::sync::mpsc::TryRecvError::Empty) => {}

            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.chain_scan_busy = false;

                self.chain_scan_rx = None;

                self.chain_scan_error = Some("chain history scanner stopped unexpectedly".into());
            }
        }
    }

    fn reload_local_history(&mut self) {
        let Some(w) = self.wallet.as_ref() else {
            self.sent_history.clear();
            return;
        };

        self.sent_history = prefs::load_history(&w.address);
    }

    fn refresh_mempool(&mut self) {
        let Some(w) = self.wallet.as_ref() else {
            self.mempool_txids.clear();
            return;
        };

        match rpc::mempool_get_by_sender(&w.address) {
            Ok(txs) => {
                self.mempool_txids = txs.into_iter().map(|tx| tx.txid).collect();
            }

            Err(_) => {
                self.mempool_txids.clear();
            }
        }
    }

    fn open_wallet_path(&mut self, path: &std::path::Path) -> Result<(), String> {
        let w = wallet::open_wallet(path)?;

        prefs::save_last_wallet(&w.path)?;

        self.wallet_unlocked = !w.encrypted;

        self.wallet = Some(w);
        self.reload_local_history();
        self.wallet_error = None;

        self.refresh_account();

        Ok(())
    }

    fn choose_wallet(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Plaine wallet", &["plnekey"])
            .pick_file()
        else {
            return;
        };

        if let Err(e) = self.open_wallet_path(&path) {
            self.wallet_error = Some(e);
        }
    }

    fn finish_new_wallet(&mut self, created: wallet::CreatedWallet) {
        let wallet = created.wallet;

        if let Err(e) = prefs::save_last_wallet(&wallet.path) {
            self.wallet_error = Some(e);
        }

        self.pending_backup = Some(created.backup);

        self.wallet_unlocked = !wallet.encrypted;

        self.wallet = Some(wallet);

        self.reload_local_history();
        self.load_chain_history();

        self.refresh_account();
        self.refresh_mempool();

        self.start_chain_scan();
    }

    fn create_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_create_dialog {
            return;
        }

        let mut open = true;

        egui::Window::new("CREATE WALLET")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label("Password (optional)");

                ui.add(
                    egui::TextEdit::singleline(&mut self.create_password)
                        .password(true)
                        .desired_width(320.0),
                );

                ui.label("Repeat password");

                ui.add(
                    egui::TextEdit::singleline(&mut self.create_password2)
                        .password(true)
                        .desired_width(320.0),
                );

                ui.add_space(12.0);

                if ui.button("CREATE").clicked() {
                    if self.create_password != self.create_password2 {
                        self.wallet_error = Some("passwords do not match".into());
                        return;
                    }

                    let Some(path) = rfd::FileDialog::new()
                        .set_file_name("wallet.plnekey")
                        .add_filter("Plaine wallet", &["plnekey"])
                        .save_file()
                    else {
                        return;
                    };

                    let password = self.create_password.clone();

                    let pass = if password.is_empty() {
                        None
                    } else {
                        Some(password.as_str())
                    };

                    if path.exists() {
                        self.pending_overwrite = Some(PendingOverwrite::Create { path, password });

                        self.show_create_dialog = false;
                        return;
                    }

                    match wallet::create_wallet(&path, pass) {
                        Ok(created) => {
                            self.finish_new_wallet(created);

                            self.wallet_error = None;

                            self.show_create_dialog = false;

                            self.create_password.clear();
                            self.create_password2.clear();
                        }

                        Err(e) => {
                            self.wallet_error = Some(e);
                        }
                    }
                }
            });

        if !open {
            self.show_create_dialog = false;
        }
    }

    fn import_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_import_dialog {
            return;
        }

        let mut open = true;

        egui::Window::new("IMPORT PLAINE BACKUP")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label("Plaine backup secret");

                ui.add(egui::TextEdit::singleline(&mut self.import_backup).desired_width(520.0));

                ui.add_space(6.0);

                ui.label("Password for the new wallet file (optional)");

                ui.add(
                    egui::TextEdit::singleline(&mut self.import_password)
                        .password(true)
                        .desired_width(320.0),
                );

                ui.add_space(12.0);

                if ui.button("IMPORT").clicked() {
                    let Some(path) = rfd::FileDialog::new()
                        .set_file_name("wallet.plnekey")
                        .add_filter("Plaine wallet", &["plnekey"])
                        .save_file()
                    else {
                        return;
                    };

                    let password = self.import_password.clone();

                    let pass = if password.is_empty() {
                        None
                    } else {
                        Some(password.as_str())
                    };

                    if path.exists() {
                        self.pending_overwrite = Some(PendingOverwrite::Import {
                            path,
                            backup: self.import_backup.trim().to_string(),
                            password,
                        });

                        self.show_import_dialog = false;
                        return;
                    }

                    match wallet::import_backup(&path, self.import_backup.trim(), pass) {
                        Ok(w) => {
                            if let Err(e) = prefs::save_last_wallet(&w.path) {
                                self.wallet_error = Some(e);
                            }

                            self.wallet = Some(w);
                            self.wallet_error = None;

                            self.refresh_account();

                            self.show_import_dialog = false;

                            self.import_backup.clear();
                            self.import_password.clear();
                        }

                        Err(e) => {
                            self.wallet_error = Some(e);
                        }
                    }
                }
            });

        if !open {
            self.show_import_dialog = false;
        }
    }

    fn backup_dialog(&mut self, ctx: &egui::Context) {
        let Some(backup) = self.pending_backup.clone() else {
            return;
        };

        egui::Window::new(
            "SAVE YOUR PLAINE BACKUP"
        )
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new(
                    "THIS SECRET RESTORES YOUR WALLET"
                )
                .strong(),
            );

            ui.add_space(8.0);

            ui.label(
                "Store it somewhere safe. Anyone with this secret can restore and spend this wallet."
            );

            ui.add_space(14.0);

            let mut text = backup.clone();

            ui.add(
                egui::TextEdit::singleline(
                    &mut text
                )
                .desired_width(600.0)
                .interactive(false),
            );

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui
                    .button("COPY BACKUP")
                    .clicked()
                {
                    ui.ctx()
                        .copy_text(
                            backup.clone()
                        );
                }

                if ui
                    .button(
                        "I HAVE SAVED THIS BACKUP"
                    )
                    .clicked()
                {
                    self.pending_backup = None;
                }
            });
        });
    }

    fn overwrite_warning_dialog(&mut self, ctx: &egui::Context) {
        let Some(action) = self.pending_overwrite.as_ref() else {
            return;
        };

        let path_text = match action {
            PendingOverwrite::Create { path, .. } => path.display().to_string(),

            PendingOverwrite::Import { path, .. } => path.display().to_string(),
        };

        let mut cancel = false;
        let mut confirm = false;

        egui::Window::new(
            "DANGER — EXISTING WALLET"
        )
        .collapsible(false)
        .resizable(false)
        .frame(
            egui::Frame::new()
                .fill(egui::Color32::WHITE)
                .stroke(
                    egui::Stroke::new(
                        3.0_f32,
                        egui::Color32::RED,
                    )
                )
                .inner_margin(
                    egui::Margin::same(20)
                ),
        )
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new(
                    "WARNING: THIS WALLET FILE ALREADY EXISTS"
                )
                .color(egui::Color32::RED)
                .strong()
                .size(18.0),
            );

            ui.add_space(12.0);

            ui.label(
                egui::RichText::new(
                    "The existing wallet may contain funds."
                )
                .color(egui::Color32::RED)
                .strong(),
            );

            ui.add_space(6.0);

            ui.label(
                egui::RichText::new(
                    "Overwriting it will permanently replace the wallet file."
                )
                .color(egui::Color32::RED),
            );

            ui.label(
                egui::RichText::new(
                    "If you do not have a valid backup, access to funds in the existing wallet may be permanently lost."
                )
                .color(egui::Color32::RED),
            );

            ui.add_space(14.0);

            ui.monospace(
                format!(
                    "FILE:\n{}",
                    path_text
                )
            );

            ui.add_space(18.0);

            ui.horizontal(|ui| {
                if ui
                    .button("CANCEL")
                    .clicked()
                {
                    cancel = true;
                }

                let overwrite =
                    egui::Button::new(
                        egui::RichText::new(
                            "YES, PERMANENTLY OVERWRITE WALLET"
                        )
                        .color(
                            egui::Color32::RED
                        )
                        .strong(),
                    )
                    .stroke(
                        egui::Stroke::new(
                            2.0_f32,
                            egui::Color32::RED,
                        )
                    );

                if ui.add(overwrite).clicked() {
                    confirm = true;
                }
            });
        });

        if cancel {
            self.pending_overwrite = None;
            return;
        }

        if !confirm {
            return;
        }

        let Some(action) = self.pending_overwrite.take() else {
            return;
        };

        match action {
            PendingOverwrite::Create { path, password } => {
                let pass = if password.is_empty() {
                    None
                } else {
                    Some(password.as_str())
                };

                match wallet::create_wallet_replace(&path, pass) {
                    Ok(created) => {
                        self.finish_new_wallet(created);

                        self.wallet_error = None;

                        self.create_password.clear();
                        self.create_password2.clear();
                    }

                    Err(e) => {
                        self.wallet_error = Some(e);
                    }
                }
            }

            PendingOverwrite::Import {
                path,
                backup,
                password,
            } => {
                let pass = if password.is_empty() {
                    None
                } else {
                    Some(password.as_str())
                };

                match wallet::import_backup_replace(&path, &backup, pass) {
                    Ok(w) => {
                        let _ = prefs::save_last_wallet(&w.path);

                        self.wallet = Some(w);
                        self.wallet_error = None;

                        self.refresh_account();

                        self.import_backup.clear();
                        self.import_password.clear();
                    }

                    Err(e) => {
                        self.wallet_error = Some(e);
                    }
                }
            }
        }
    }

    fn lock_wallet(&mut self) {
        self.wallet_unlocked = false;
        self.wallet_session = None;

        self.unlock_password.clear();
        self.send_password.clear();
        self.backup_password.clear();
        self.old_wallet_password.clear();
        self.new_wallet_password.clear();
        self.new_wallet_password2.clear();

        self.pending_send = None;
        self.revealed_backup = None;

        self.security_message = Some("Wallet locked.".into());
    }

    fn existing_backup_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_existing_backup_dialog {
            return;
        }

        let mut open = true;

        egui::Window::new("BACKUP WALLET")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                let Some(w) = self.wallet.as_ref() else {
                    ui.label("No wallet open.");
                    return;
                };

                ui.label(egui::RichText::new("PRIVATE BACKUP SECRET").strong());

                ui.add_space(8.0);

                ui.label("Anyone with this secret can restore and spend this wallet.");

                if w.encrypted && self.revealed_backup.is_none() {
                    ui.add_space(12.0);

                    ui.label("Wallet password");

                    ui.add(
                        egui::TextEdit::singleline(&mut self.backup_password)
                            .password(true)
                            .desired_width(320.0),
                    );
                }

                ui.add_space(12.0);

                if self.revealed_backup.is_none() {
                    if ui.button("REVEAL BACKUP SECRET").clicked() {
                        if w.encrypted && !self.wallet_unlocked {
                            self.security_message =
                                Some("Unlock the wallet before revealing the backup.".into());
                            self.show_unlock_dialog = true;
                            return;
                        }

                        let session = if w.encrypted {
                            self.wallet_session.as_ref()
                        } else {
                            None
                        };

                        match wallet::backup_secret_session(w, session) {
                            Ok(secret) => {
                                self.revealed_backup = Some(secret);

                                self.backup_password.clear();

                                self.security_message = None;
                            }

                            Err(e) => {
                                self.security_message = Some(format!("Backup failed: {e}"));
                            }
                        }
                    }
                }

                if let Some(secret) = self.revealed_backup.as_ref() {
                    ui.add_space(15.0);

                    let mut shown = secret.clone();

                    ui.add(
                        egui::TextEdit::singleline(&mut shown)
                            .desired_width(610.0)
                            .interactive(false),
                    );

                    ui.add_space(8.0);

                    if ui.button("COPY BACKUP").clicked() {
                        ui.ctx().copy_text(secret.clone());
                    }
                }
            });

        if !open {
            self.show_existing_backup_dialog = false;

            self.backup_password.clear();
            self.revealed_backup = None;
        }
    }

    fn poll_security_task(&mut self) {
        let Some(rx) = self.security_rx.as_ref() else {
            return;
        };

        match rx.try_recv() {
            Ok(result) => {
                self.security_busy = false;
                self.security_rx = None;

                match result {
                    Ok(updated) => {
                        let path = updated.path.clone();

                        let _ = prefs::save_last_wallet(&path);

                        self.wallet = Some(updated);

                        self.security_message =
                            Some("Wallet encryption updated and verified successfully.".into());

                        self.old_wallet_password.clear();
                        self.new_wallet_password.clear();
                        self.new_wallet_password2.clear();

                        self.remove_wallet_encryption = false;

                        self.refresh_account();
                    }

                    Err(e) => {
                        self.security_message = Some(format!("Encryption change failed: {e}"));
                    }
                }
            }

            Err(std::sync::mpsc::TryRecvError::Empty) => {}

            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.security_busy = false;
                self.security_rx = None;

                self.security_message = Some("Encryption worker stopped unexpectedly.".into());
            }
        }
    }

    fn passphrase_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_passphrase_dialog {
            return;
        }

        let mut open = true;

        egui::Window::new(
            "WALLET ENCRYPTION"
        )
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
            let Some(w) =
                self.wallet.as_ref()
            else {
                return;
            };

            let encrypted = w.encrypted;

            ui.monospace(
                if encrypted {
                    "CURRENT STATUS: ENCRYPTED"
                } else {
                    "CURRENT STATUS: UNENCRYPTED"
                }
            );

            if self.security_busy {
                ui.add_space(15.0);

                ui.label(
                    egui::RichText::new(
                        "WORKING — DO NOT CLOSE THE APPLICATION"
                    )
                    .strong()
                );

                ui.spinner();

                return;
            }

            if encrypted {
                ui.add_space(12.0);

                ui.label(
                    "Current password"
                );

                ui.add(
                    egui::TextEdit::singleline(
                        &mut self.old_wallet_password
                    )
                    .password(true)
                    .desired_width(320.0)
                );
            }

            ui.add_space(12.0);

            ui.checkbox(
                &mut self.remove_wallet_encryption,
                "REMOVE ENCRYPTION"
            );

            if !self.remove_wallet_encryption {
                ui.add_space(8.0);

                ui.label(
                    if encrypted {
                        "New password"
                    } else {
                        "Set password"
                    }
                );

                ui.add(
                    egui::TextEdit::singleline(
                        &mut self.new_wallet_password
                    )
                    .password(true)
                    .desired_width(320.0)
                );

                ui.label(
                    "Repeat new password"
                );

                ui.add(
                    egui::TextEdit::singleline(
                        &mut self.new_wallet_password2
                    )
                    .password(true)
                    .desired_width(320.0)
                );
            } else {
                ui.add_space(8.0);

                ui.label(
                    egui::RichText::new(
                        "WARNING: the private seed will be stored in the wallet file without encryption."
                    )
                    .color(
                        egui::Color32::RED
                    )
                    .strong()
                );
            }

            ui.add_space(15.0);

            if ui
                .button(
                    "APPLY WALLET ENCRYPTION CHANGE"
                )
                .clicked()
            {
                if !self.remove_wallet_encryption
                    && self.new_wallet_password
                        != self.new_wallet_password2
                {
                    self.security_message =
                        Some(
                            "New passwords do not match."
                                .into()
                        );

                    return;
                }

                if !self.remove_wallet_encryption
                    && self.new_wallet_password
                        .is_empty()
                {
                    self.security_message =
                        Some(
                            "New password cannot be empty. Use REMOVE ENCRYPTION if that is intentional."
                                .into()
                        );

                    return;
                }

                let wallet =
                    w.clone();

                let old =
                    if encrypted {
                        Some(
                            self.old_wallet_password
                                .clone()
                        )
                    } else {
                        None
                    };

                let new =
                    if self.remove_wallet_encryption {
                        None
                    } else {
                        Some(
                            self.new_wallet_password
                                .clone()
                        )
                    };

                let (tx, rx) =
                    std::sync::mpsc::channel();

                self.security_busy = true;
                self.security_rx = Some(rx);

                self.security_message =
                    Some(
                        "Updating wallet encryption..."
                            .into()
                    );

                std::thread::spawn(
                    move || {
                        let result =
                            wallet::change_passphrase_in_place(
                                &wallet,
                                old.as_deref(),
                                new.as_deref(),
                            );

                        let _ =
                            tx.send(result);
                    }
                );
            }
        });

        if !open && !self.security_busy {
            self.show_passphrase_dialog = false;

            self.old_wallet_password.clear();
            self.new_wallet_password.clear();
            self.new_wallet_password2.clear();

            self.remove_wallet_encryption = false;
        }
    }

    fn unlock_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_unlock_dialog {
            return;
        }

        let mut open = true;

        egui::Window::new("UNLOCK WALLET")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label("Wallet password");

                ui.add(
                    egui::TextEdit::singleline(&mut self.unlock_password)
                        .password(true)
                        .desired_width(320.0),
                );

                ui.add_space(12.0);

                if ui.button("UNLOCK").clicked() {
                    let Some(w) = self.wallet.as_ref() else {
                        return;
                    };

                    if !w.encrypted {
                        self.wallet_unlocked = true;
                        self.wallet_session = None;
                        self.show_unlock_dialog = false;
                        self.unlock_password.clear();
                        return;
                    }

                    let secret = wallet::make_secret_passphrase(&self.unlock_password);

                    match wallet::verify_secret_passphrase(w, &secret) {
                        Ok(()) => {
                            self.wallet_unlocked = true;
                            self.wallet_session = Some(secret);

                            self.show_unlock_dialog = false;

                            self.security_message = Some("Wallet unlocked.".into());
                        }

                        Err(e) => {
                            self.security_message = Some(format!("Unlock failed: {e}"));
                        }
                    }

                    self.unlock_password.clear();
                }
            });

        if !open {
            self.show_unlock_dialog = false;
            self.unlock_password.clear();
        }
    }

    fn wallet_screen(&mut self, ui: &mut egui::Ui) {
        ui.monospace("WALLET / MAIN");
        ui.add_space(20.0);

        if self.wallet.is_none() {
            ui.heading("No wallet open");

            ui.add_space(12.0);

            ui.horizontal(|ui| {
                if ui.button("OPEN .PLNEKEY").clicked() {
                    self.choose_wallet();
                }

                if ui.button("CREATE NEW WALLET").clicked() {
                    self.show_create_dialog = true;
                }

                if ui.button("IMPORT BACKUP").clicked() {
                    self.show_import_dialog = true;
                }
            });

            if let Some(error) = &self.wallet_error {
                ui.add_space(15.0);

                ui.monospace(format!("ERROR: {error}"));
            }

            return;
        }

        let w = self.wallet.as_ref().unwrap();

        let balance = self
            .account
            .as_ref()
            .map(|a| format_mile(&a.balance))
            .unwrap_or_else(|| "—".into());

        let spendable = self
            .account
            .as_ref()
            .map(|a| format_mile(&a.spendable))
            .unwrap_or_else(|| "—".into());

        let immature = self
            .account
            .as_ref()
            .map(|a| format_mile(&a.immature))
            .unwrap_or_else(|| "—".into());

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(balance).size(46.0));

            ui.label("PLNE");
        });

        ui.add_space(25.0);

        ui.columns(2, |cols| {
            info_box(&mut cols[0], "SPENDABLE", &format!("{spendable} PLNE"));

            info_box(&mut cols[1], "IMMATURE", &format!("{immature} PLNE"));
        });

        ui.add_space(14.0);

        info_box(ui, "ADDRESS", &w.address);

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.monospace(if w.encrypted {
                "KEYFILE: ENCRYPTED"
            } else {
                "KEYFILE: UNENCRYPTED"
            });

            ui.separator();

            ui.monospace(w.path.display().to_string());
        });

        ui.add_space(8.0);

        let wallet_encrypted = w.encrypted;
        let wallet_unlocked = self.wallet_unlocked;

        let mut do_lock = false;
        let mut do_unlock = false;

        ui.horizontal(|ui| {
            if wallet_encrypted {
                ui.monospace(if wallet_unlocked {
                    "STATE: UNLOCKED"
                } else {
                    "STATE: LOCKED"
                });

                ui.separator();

                if wallet_unlocked {
                    if ui.button("LOCK WALLET").clicked() {
                        do_lock = true;
                    }
                } else {
                    if ui.button("UNLOCK WALLET").clicked() {
                        do_unlock = true;
                    }
                }
            } else {
                ui.monospace("STATE: UNLOCKED (UNENCRYPTED)");
            }
        });

        if do_lock {
            self.lock_wallet();
        }

        if do_unlock {
            self.show_unlock_dialog = true;
        }

        if let Some(account) = &self.account {
            ui.add_space(8.0);

            ui.monospace(format!(
                "NONCE {} / PENDING {}",
                account.nonce, account.pending_nonce
            ));
        }
    }

    fn prepare_send(&mut self) {
        self.send_error = None;
        self.send_result = None;

        let Some(w) = self.wallet.as_ref() else {
            self.send_error = Some("Open a wallet first.".into());
            return;
        };

        if w.encrypted && !self.wallet_unlocked {
            self.send_error = Some("Wallet is locked. Unlock it before sending.".into());
            self.show_unlock_dialog = true;
            return;
        };

        let to = self.send_to.trim().to_string();

        if to.is_empty() {
            self.send_error = Some("Recipient address is required.".into());
            return;
        }

        let amount_mile = match parse_plne_to_mile(self.send_amount.trim()) {
            Ok(v) if v > 0 => v,

            Ok(_) => {
                self.send_error = Some("Amount must be greater than zero.".into());
                return;
            }

            Err(e) => {
                self.send_error = Some(e);
                return;
            }
        };

        let account = match rpc::account_get(&w.address) {
            Ok(v) => v,

            Err(e) => {
                self.send_error = Some(e);
                return;
            }
        };

        self.account = Some(account.clone());

        let fees = match rpc::fee_suggest() {
            Ok(v) => v,

            Err(e) => {
                self.send_error = Some(e);
                return;
            }
        };

        let fee_text = match self.send_fee_level {
            FeeLevel::Economy => &fees.p10_mile,

            FeeLevel::Normal => &fees.p50_mile,

            FeeLevel::Priority => &fees.p90_mile,
        };

        let fee_mile = match fee_text.parse::<u128>() {
            Ok(v) => v,

            Err(_) => {
                self.send_error = Some("Node returned an invalid fee.".into());
                return;
            }
        };

        let spendable = match account.spendable.parse::<u128>() {
            Ok(v) => v,

            Err(_) => {
                self.send_error = Some("Invalid spendable balance returned by node.".into());
                return;
            }
        };

        let needed = match amount_mile.checked_add(fee_mile) {
            Some(v) => v,

            None => {
                self.send_error = Some("Amount overflow.".into());
                return;
            }
        };

        if needed > spendable {
            self.send_error = Some(format!(
                "Insufficient funds. Required {} PLNE including fee, spendable {} PLNE.",
                format_mile_u128(needed),
                format_mile_u128(spendable),
            ));

            return;
        }

        let session = if w.encrypted {
            self.wallet_session.as_ref()
        } else {
            None
        };

        let raw_hex = match wallet::build_transfer_raw_session(
            w,
            session,
            &to,
            amount_mile,
            fee_mile,
            account.pending_nonce,
        ) {
            Ok(v) => v,

            Err(e) => {
                self.send_error = Some(format!("Cannot sign transaction: {e}"));

                return;
            }
        };

        self.pending_send = Some(PendingSend {
            raw_hex,
            to,
            amount_mile,
            fee_mile,
            nonce: account.pending_nonce,
        });

        // Once signed, the password is no longer needed.
        self.send_password.clear();
    }

    fn send_confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(tx) = self.pending_send.as_ref() else {
            return;
        };

        let to = tx.to.clone();
        let amount_mile = tx.amount_mile;
        let fee_mile = tx.fee_mile;
        let nonce = tx.nonce;

        let mut cancel = false;
        let mut broadcast = false;

        egui::Window::new("CONFIRM TRANSACTION")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new("REVIEW BEFORE SENDING")
                        .strong()
                        .size(17.0),
                );

                ui.add_space(15.0);

                ui.monospace("TO");
                ui.label(&to);

                ui.add_space(12.0);

                ui.monospace("AMOUNT");
                ui.label(format!("{} PLNE", format_mile_u128(amount_mile)));

                ui.add_space(12.0);

                ui.monospace("NETWORK FEE");
                ui.label(format!(
                    "{} PLNE  ({} mile)",
                    format_mile_u128(fee_mile),
                    fee_mile
                ));

                ui.add_space(12.0);

                ui.monospace(format!("NONCE {nonce}"));

                ui.add_space(18.0);

                ui.label("A submitted transaction cannot be reversed.");

                ui.add_space(18.0);

                ui.horizontal(|ui| {
                    if ui.button("CANCEL").clicked() {
                        cancel = true;
                    }

                    if ui.button("BROADCAST TRANSACTION").clicked() {
                        broadcast = true;
                    }
                });
            });

        if cancel {
            self.pending_send = None;
            return;
        }

        if !broadcast {
            return;
        }

        let Some(tx) = self.pending_send.take() else {
            return;
        };

        match rpc::tx_send_raw(&tx.raw_hex) {
            Ok(txid) => {
                if let Some(w) = self.wallet.as_ref() {
                    let entry = prefs::SentTx {
                        txid: txid.clone(),
                        to: tx.to.clone(),
                        amount_mile: tx.amount_mile,
                        fee_mile: tx.fee_mile,
                        nonce: tx.nonce,
                        created_at: unix_time_secs(),
                    };

                    match prefs::push_sent_tx(&w.address, entry) {
                        Ok(history) => {
                            self.sent_history = history;
                        }

                        Err(e) => {
                            self.send_error = Some(format!(
                                "Transaction was sent, but local history could not be saved: {e}"
                            ));
                        }
                    }
                }

                self.send_result = Some(txid);

                self.send_to.clear();
                self.send_amount.clear();
                self.send_password.clear();

                self.refresh_account();
                self.refresh_mempool();
            }

            Err(e) => {
                self.send_error = Some(format!("Broadcast failed: {e}"));
            }
        }
    }

    fn send_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("SEND");

        ui.add_space(15.0);

        let Some(w) = self.wallet.as_ref() else {
            ui.label("Open a wallet first.");
            return;
        };

        ui.monospace(format!("FROM {}", w.address));

        if let Some(account) = self.account.as_ref() {
            ui.add_space(6.0);

            ui.monospace(format!(
                "SPENDABLE {} PLNE",
                format_mile(&account.spendable)
            ));
        }

        ui.add_space(20.0);

        ui.label("Recipient");

        ui.add(
            egui::TextEdit::singleline(&mut self.send_to)
                .desired_width(620.0)
                .hint_text("plne1..."),
        );

        ui.add_space(12.0);

        ui.label("Amount (PLNE)");

        ui.add(
            egui::TextEdit::singleline(&mut self.send_amount)
                .desired_width(220.0)
                .hint_text("1.000000"),
        );

        ui.add_space(18.0);

        ui.label("Fee");

        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;

            let fee_button = |label: &str, selected: bool| -> egui::Button<'_> {
                egui::Button::new(egui::RichText::new(label).strong().color(if selected {
                    egui::Color32::WHITE
                } else {
                    egui::Color32::BLACK
                }))
                .fill(if selected {
                    egui::Color32::from_rgb(18, 18, 18)
                } else {
                    egui::Color32::WHITE
                })
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    if selected {
                        egui::Color32::BLACK
                    } else {
                        egui::Color32::from_rgb(195, 195, 190)
                    },
                ))
                .corner_radius(egui::CornerRadius::same(8))
            };

            let economy = self.send_fee_level == FeeLevel::Economy;

            let normal = self.send_fee_level == FeeLevel::Normal;

            let priority = self.send_fee_level == FeeLevel::Priority;

            if ui
                .add_sized([110.0, 38.0], fee_button("ECONOMY", economy))
                .clicked()
            {
                self.send_fee_level = FeeLevel::Economy;
            }

            if ui
                .add_sized([110.0, 38.0], fee_button("NORMAL", normal))
                .clicked()
            {
                self.send_fee_level = FeeLevel::Normal;
            }

            if ui
                .add_sized([110.0, 38.0], fee_button("PRIORITY", priority))
                .clicked()
            {
                self.send_fee_level = FeeLevel::Priority;
            }
        });

        if let Ok(fees) = rpc::fee_suggest() {
            let selected = match self.send_fee_level {
                FeeLevel::Economy => &fees.p10_mile,

                FeeLevel::Normal => &fees.p50_mile,

                FeeLevel::Priority => &fees.p90_mile,
            };

            ui.add_space(8.0);

            ui.monospace(format!(
                "SELECTED FEE: {} mile  |  relay floor: {} mile",
                selected, fees.relay_floor_mile
            ));
        }

        ui.add_space(24.0);

        let review = egui::Button::new(
            egui::RichText::new("REVIEW TRANSACTION")
                .strong()
                .color(egui::Color32::WHITE),
        )
        .fill(egui::Color32::from_rgb(18, 18, 18))
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::BLACK));

        if ui.add(review).clicked() {
            self.prepare_send();
        }

        if let Some(error) = &self.send_error {
            ui.add_space(15.0);

            ui.label(egui::RichText::new(error).color(egui::Color32::RED));
        }

        if let Some(txid) = &self.send_result {
            ui.add_space(20.0);

            ui.label(egui::RichText::new("TRANSACTION SUBMITTED").strong());

            ui.add_space(8.0);

            ui.monospace(txid);

            if ui.button("COPY TXID").clicked() {
                ui.ctx().copy_text(txid.clone());
            }
        }
    }

    fn receive_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("RECEIVE");
        ui.add_space(15.0);

        if let Some(w) = &self.wallet {
            ui.label("Your Plaine address:");

            ui.add_space(8.0);

            let mut address = w.address.clone();

            ui.add(
                egui::TextEdit::singleline(&mut address)
                    .desired_width(600.0)
                    .interactive(false),
            );

            if ui.button("COPY ADDRESS").clicked() {
                ui.ctx().copy_text(w.address.clone());
            }
        } else {
            ui.label("Open a wallet first.");
        }
    }

    fn history_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("HISTORY");

        ui.add_space(12.0);

        let Some(wallet) = self.wallet.as_ref() else {
            ui.label("Open a wallet first.");
            return;
        };

        ui.monospace(format!("ADDRESS {}", wallet.address));

        if let Some(error) = &self.chain_scan_error {
            ui.add_space(8.0);

            ui.label(egui::RichText::new(error).color(egui::Color32::RED));
        }

        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let confirmed_ids: std::collections::HashSet<&str> = self
                    .chain_history
                    .iter()
                    .map(|tx| tx.txid.as_str())
                    .collect();

                // Pending / waiting transactions.
                for tx in self.sent_history.iter() {
                    if confirmed_ids.contains(tx.txid.as_str()) {
                        continue;
                    }

                    let status = if self.mempool_txids.contains(&tx.txid) {
                        "PENDING"
                    } else {
                        "WAITING"
                    };

                    history_pending_row(ui, tx, status);

                    ui.add_space(10.0);
                }

                // Confirmed blockchain history.
                for tx in &self.chain_history {
                    history_chain_row(ui, tx);

                    ui.add_space(10.0);
                }

                if self.sent_history.is_empty() && self.chain_history.is_empty() {
                    ui.label("No wallet transactions found.");
                }

                // trochę miejsca na dole żeby ostatni wpis
                // nie był przycięty
                ui.add_space(30.0);
            });
    }

    fn settings_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("SETTINGS");
        ui.add_space(15.0);

        ui.monospace("Node: embedded");
        ui.monospace("RPC: 127.0.0.1:9257");

        ui.add_space(24.0);

        ui.label(egui::RichText::new("WALLET MANAGEMENT").strong());

        ui.add_space(10.0);

        ui.horizontal_wrapped(|ui| {
            if ui.button("OPEN ANOTHER WALLET").clicked() {
                self.choose_wallet();
            }

            if ui.button("CREATE NEW WALLET").clicked() {
                self.show_create_dialog = true;
            }

            if ui.button("IMPORT BACKUP").clicked() {
                self.show_import_dialog = true;
            }
        });

        ui.add_space(24.0);

        let Some(w) = self.wallet.as_ref() else {
            ui.label("No wallet open.");

            if let Some(wallet) = self.wallet.as_ref() {
                ui.monospace(format!("WALLET ROLE: {:?}", wallet.role));
            }

            if let Some(msg) = &self.security_message {
                ui.add_space(10.0);
                ui.label(msg);
            }

            return;
        };

        let wallet_path = w.path.clone();
        let wallet_address = w.address.clone();
        let wallet_encrypted = w.encrypted;

        ui.label(egui::RichText::new("CURRENT WALLET").strong());

        ui.add_space(10.0);

        ui.monospace(format!("Wallet: {}", wallet_path.display()));

        ui.monospace(format!("Address: {}", wallet_address));

        ui.monospace(if wallet_encrypted {
            "Encryption: ENABLED"
        } else {
            "Encryption: DISABLED"
        });

        ui.add_space(20.0);

        let mut do_backup = false;
        let mut do_passphrase = false;

        ui.horizontal_wrapped(|ui| {
            if ui.button("BACKUP WALLET").clicked() {
                do_backup = true;
            }

            if ui
                .button(if wallet_encrypted {
                    "CHANGE PASSWORD"
                } else {
                    "ENCRYPT WALLET"
                })
                .clicked()
            {
                do_passphrase = true;
            }
        });

        if do_backup {
            self.revealed_backup = None;
            self.backup_password.clear();
            self.show_existing_backup_dialog = true;
        }

        if do_passphrase {
            self.show_passphrase_dialog = true;
        }

        if let Some(msg) = &self.security_message {
            ui.add_space(18.0);
            ui.label(msg);
        }
    }
}

impl eframe::App for PlaineApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_plaine_theme(ctx);

        let _keep_node_alive = self.embedded_node.is_some();

        if self.last_rpc_update.elapsed() >= Duration::from_secs(3) {
            self.refresh_node();
        }

        if self.wallet.is_some()
            && !self.chain_scan_busy
            && self.last_chain_scan.elapsed() >= Duration::from_secs(60)
        {
            self.start_chain_scan();
        }

        ctx.request_repaint_after(Duration::from_secs(1));

        self.poll_security_task();
        self.poll_chain_scan();

        self.create_dialog(ctx);
        self.import_dialog(ctx);
        self.overwrite_warning_dialog(ctx);
        self.backup_dialog(ctx);
        self.send_confirm_dialog(ctx);
        self.existing_backup_dialog(ctx);
        self.passphrase_dialog(ctx);
        self.unlock_dialog(ctx);

        top_bar(ctx, self.chain.as_ref());

        egui::SidePanel::left("sidebar")
            .exact_width(160.0)
            .show(ctx, |ui| {
                ui.add_space(20.0);

                nav(ui, &mut self.screen, Screen::Wallet, "WALLET");

                nav(ui, &mut self.screen, Screen::Send, "SEND");

                nav(ui, &mut self.screen, Screen::Receive, "RECEIVE");

                nav(ui, &mut self.screen, Screen::History, "HISTORY");

                nav(ui, &mut self.screen, Screen::Settings, "SETTINGS");
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(20.0);

            match self.screen {
                Screen::Wallet => self.wallet_screen(ui),

                Screen::Send => self.send_screen(ui),

                Screen::Receive => self.receive_screen(ui),

                Screen::History => self.history_screen(ui),

                Screen::Settings => self.settings_screen(ui),
            }
        });
    }
}

fn top_bar(ctx: &egui::Context, chain: Option<&rpc::ChainInfo>) {
    egui::TopBottomPanel::top("top")
        .exact_height(72.0)
        .show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(
                    egui::RichText::new("Pla(i)n[e] Wallet")
                        .size(25.0)
                        .strong()
                        .color(egui::Color32::BLACK),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(c) = chain {
                        ui.monospace(format!(
                            "{} / HEIGHT {} / {} PEERS",
                            c.sync.to_uppercase(),
                            c.height,
                            c.peers
                        ));
                    } else {
                        ui.monospace("NODE OFFLINE");
                    }
                });
            });
        });
}

fn nav(ui: &mut egui::Ui, current: &mut Screen, screen: Screen, label: &str) {
    let selected = *current == screen;

    let fill = if selected {
        egui::Color32::from_rgb(18, 18, 18)
    } else {
        egui::Color32::TRANSPARENT
    };

    let text_color = if selected {
        egui::Color32::WHITE
    } else {
        egui::Color32::from_rgb(35, 35, 35)
    };

    let stroke = if selected {
        egui::Stroke::new(1.0_f32, egui::Color32::BLACK)
    } else {
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(220, 220, 214))
    };

    let button = egui::Button::new(
        egui::RichText::new(label)
            .size(14.0)
            .strong()
            .color(text_color),
    )
    .fill(fill)
    .stroke(stroke)
    .corner_radius(egui::CornerRadius::same(12))
    .min_size(egui::vec2(ui.available_width(), 44.0));

    if ui.add(button).clicked() {
        *current = screen;
    }
}

fn info_box(ui: &mut egui::Ui, title: &str, value: &str) {
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::BLACK))
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_min_height(85.0);

            ui.monospace(title);
            ui.add_space(14.0);
            ui.label(value);
        });
}

fn format_mile(raw: &str) -> String {
    let Ok(v) = raw.parse::<u128>() else {
        return raw.to_owned();
    };

    let whole = v / 1_000_000;

    let frac = v % 1_000_000;

    format!("{whole}.{frac:06}")
}

fn parse_plne_to_mile(input: &str) -> Result<u128, String> {
    let input = input.trim();

    if input.is_empty() {
        return Err("Amount is required.".into());
    }

    if input.starts_with('-') {
        return Err("Amount cannot be negative.".into());
    }

    let mut parts = input.split('.');

    let whole = parts.next().unwrap_or("");

    let frac = parts.next();

    if parts.next().is_some() {
        return Err("Invalid amount.".into());
    }

    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err("Invalid amount.".into());
    }

    let whole = whole
        .parse::<u128>()
        .map_err(|_| "Amount is too large.".to_string())?;

    let frac_mile = match frac {
        None => 0_u128,

        Some(f) => {
            if f.len() > 6 {
                return Err("Plaine supports at most 6 decimal places.".into());
            }

            if !f.chars().all(|c| c.is_ascii_digit()) {
                return Err("Invalid amount.".into());
            }

            let mut padded = f.to_string();

            while padded.len() < 6 {
                padded.push('0');
            }

            if padded.is_empty() {
                0
            } else {
                padded
                    .parse::<u128>()
                    .map_err(|_| "Invalid amount.".to_string())?
            }
        }
    };

    whole
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(frac_mile))
        .ok_or_else(|| "Amount is too large.".to_string())
}

fn format_mile_u128(value: u128) -> String {
    let whole = value / 1_000_000;

    let frac = value % 1_000_000;

    format!("{whole}.{frac:06}")
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn explorer_tx_url(txid: &str) -> String {
    format!("https://blacksmith.best/explorer#tx/{txid}")
}

fn history_pending_row(ui: &mut egui::Ui, tx: &prefs::SentTx, status: &str) {
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::BLACK))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            ui.horizontal(|ui| {
                ui.monospace("OUTGOING");

                ui.separator();

                ui.monospace(status);

                ui.separator();

                ui.label(format!("{} PLNE", format_mile_u128(tx.amount_mile)));
            });

            ui.add_space(9.0);

            ui.monospace("TXID");

            ui.hyperlink_to(&tx.txid, explorer_tx_url(&tx.txid));

            ui.add_space(7.0);

            ui.monospace(format!("TO {}", tx.to));

            ui.monospace(format!(
                "FEE {} PLNE  |  NONCE {}",
                format_mile_u128(tx.fee_mile),
                tx.nonce
            ));
        });
}

fn history_chain_row(ui: &mut egui::Ui, tx: &chain_history::ChainTx) {
    let direction = match tx.direction {
        chain_history::Direction::Incoming => "INCOMING",

        chain_history::Direction::Outgoing => "OUTGOING",

        chain_history::Direction::Mining => "MINING",
    };

    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::BLACK))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            ui.horizontal(|ui| {
                ui.monospace(direction);

                ui.separator();

                ui.monospace("CONFIRMED");

                ui.separator();

                ui.label(format!("{} PLNE", format_mile_u128(tx.amount_mile)));
            });

            ui.add_space(9.0);

            ui.monospace("TXID");

            ui.hyperlink_to(&tx.txid, explorer_tx_url(&tx.txid));

            ui.add_space(7.0);

            if let Some(from) = &tx.from {
                ui.monospace(format!("FROM {from}"));
            }

            ui.monospace(format!("TO {}", tx.to));

            ui.monospace(format!(
                "FEE {} PLNE  |  BLOCK {}",
                format_mile_u128(tx.fee_mile),
                tx.height
            ));
        });
}

fn apply_plaine_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::light();

    visuals.panel_fill = egui::Color32::from_rgb(248, 248, 246);
    visuals.window_fill = egui::Color32::from_rgb(252, 252, 250);
    visuals.extreme_bg_color = egui::Color32::from_rgb(243, 243, 240);
    visuals.faint_bg_color = egui::Color32::from_rgb(244, 244, 241);

    visuals.override_text_color = Some(egui::Color32::from_rgb(18, 18, 18));

    visuals.selection.bg_fill = egui::Color32::from_rgb(18, 18, 18);
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, egui::Color32::WHITE);

    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(248, 248, 246);
    visuals.widgets.noninteractive.weak_bg_fill = egui::Color32::from_rgb(248, 248, 246);
    visuals.widgets.noninteractive.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(220, 220, 214));
    visuals.widgets.noninteractive.fg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(25, 25, 25));

    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(255, 255, 255);
    visuals.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(255, 255, 255);
    visuals.widgets.inactive.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(206, 206, 198));
    visuals.widgets.inactive.fg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(25, 25, 25));

    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(245, 245, 241);
    visuals.widgets.hovered.weak_bg_fill = egui::Color32::from_rgb(245, 245, 241);
    visuals.widgets.hovered.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(155, 155, 148));
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);

    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(18, 18, 18);
    visuals.widgets.active.weak_bg_fill = egui::Color32::from_rgb(18, 18, 18);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::WHITE);

    visuals.widgets.open.bg_fill = egui::Color32::from_rgb(255, 255, 255);
    visuals.widgets.open.weak_bg_fill = egui::Color32::from_rgb(255, 255, 255);
    visuals.widgets.open.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(180, 180, 172));
    visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);

    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(10);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(10);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(10);
    visuals.widgets.open.corner_radius = egui::CornerRadius::same(10);

    visuals.window_corner_radius = egui::CornerRadius::same(16);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();

    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(16.0, 10.0);
    style.spacing.indent = 18.0;
    style.spacing.interact_size = egui::vec2(120.0, 40.0);

    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(24.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(16.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(15.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(14.0, egui::FontFamily::Monospace),
    );

    ctx.set_style(style);
}
