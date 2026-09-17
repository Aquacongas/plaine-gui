use std::path::{Path, PathBuf};

use plaine_wallet::keyfile::{self, KeyFile, Role};
use plaine_wallet::secret::{Secret32, SecretBytes};

#[derive(Debug, Clone)]
pub struct LoadedWallet {
    pub path: PathBuf,
    pub address: String,
    pub encrypted: bool,
    pub role: Role,
}

#[derive(Debug, Clone)]
pub struct CreatedWallet {
    pub wallet: LoadedWallet,
    pub backup: String,
}

pub fn open_wallet(path: &Path) -> Result<LoadedWallet, String> {
    let keyfile: KeyFile = keyfile::read(path).map_err(|e| e.to_string())?;

    if keyfile.role != Role::Spend {
        return Err(format!(
            "this is a '{}' key, not a spend wallet",
            keyfile.role.as_str()
        ));
    }

    Ok(LoadedWallet {
        path: path.to_path_buf(),
        address: keyfile.address.clone(),
        encrypted: !keyfile.is_unencrypted(),
        role: keyfile.role,
    })
}

pub fn create_wallet(path: &Path, passphrase: Option<&str>) -> Result<CreatedWallet, String> {
    if path.exists() {
        return Err("wallet file already exists".into());
    }

    let seed = plaine_wallet::rng::generate_seed().map_err(|e| e.to_string())?;

    let backup = plaine_wallet::sechex::encode_backup(&seed);

    let wallet = create_from_seed(path, &seed, passphrase)?;

    Ok(CreatedWallet { wallet, backup })
}

pub fn create_wallet_replace(
    path: &Path,
    passphrase: Option<&str>,
) -> Result<CreatedWallet, String> {
    let seed = plaine_wallet::rng::generate_seed().map_err(|e| e.to_string())?;

    let backup = plaine_wallet::sechex::encode_backup(&seed);

    replace_from_seed(path, &seed, passphrase)?;

    let wallet = open_wallet(path)?;

    Ok(CreatedWallet { wallet, backup })
}

pub fn import_backup(
    path: &Path,
    backup: &str,
    passphrase: Option<&str>,
) -> Result<LoadedWallet, String> {
    if path.exists() {
        return Err("wallet file already exists".into());
    }

    let (seed, _source) =
        plaine_wallet::sechex::decode_backup(backup.trim()).map_err(|e| e.to_string())?;

    create_from_seed(path, &seed, passphrase)
}

pub fn import_backup_replace(
    path: &Path,
    backup: &str,
    passphrase: Option<&str>,
) -> Result<LoadedWallet, String> {
    let (seed, _source) =
        plaine_wallet::sechex::decode_backup(backup.trim()).map_err(|e| e.to_string())?;

    replace_from_seed(path, &seed, passphrase)?;

    open_wallet(path)
}

fn secret_passphrase(passphrase: Option<&str>) -> Option<SecretBytes> {
    passphrase.map(|p| SecretBytes::from_vec(p.as_bytes().to_vec()))
}

fn create_from_seed(
    path: &Path,
    seed: &Secret32,
    passphrase: Option<&str>,
) -> Result<LoadedWallet, String> {
    let pass = secret_passphrase(passphrase);

    let iters = if pass.is_some() {
        plaine_wallet::kdf::DEFAULT_ITERS
    } else {
        0
    };

    let kf = KeyFile::seal(
        Role::Spend,
        plaine_wallet::now_secs(),
        seed,
        pass.as_ref(),
        iters,
    )
    .map_err(|e| e.to_string())?;

    keyfile::create_verified(path, &kf, pass.as_ref(), &kf.pubkey).map_err(|e| e.to_string())?;

    Ok(LoadedWallet {
        path: path.to_path_buf(),
        address: kf.address.clone(),
        encrypted: !kf.is_unencrypted(),
        role: kf.role,
    })
}

fn replace_from_seed(path: &Path, seed: &Secret32, passphrase: Option<&str>) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let filename = path
        .file_name()
        .ok_or_else(|| "invalid wallet path".to_string())?
        .to_string_lossy();

    let unique = format!("{}-{}", std::process::id(), plaine_wallet::now_secs());

    let temp = parent.join(format!(".{filename}.new-{unique}"));

    let old = parent.join(format!(".{filename}.old-{unique}"));

    if temp.exists() {
        let _ = std::fs::remove_file(&temp);
    }

    if old.exists() {
        let _ = std::fs::remove_file(&old);
    }

    // First create and verify the NEW wallet.
    create_from_seed(&temp, seed, passphrase)?;

    let had_old = path.exists();

    if had_old {
        std::fs::rename(path, &old).map_err(|e| {
            let _ = std::fs::remove_file(&temp);

            format!("cannot move existing wallet out of the way: {e}")
        })?;
    }

    if let Err(e) = std::fs::rename(&temp, path) {
        if had_old {
            let _ = std::fs::rename(&old, path);
        }

        let _ = std::fs::remove_file(&temp);

        return Err(format!("cannot replace wallet file: {e}"));
    }

    if had_old {
        let _ = std::fs::remove_file(&old);
    }

    Ok(())
}

pub fn change_passphrase_in_place(
    wallet: &LoadedWallet,
    old_passphrase: Option<&str>,
    new_passphrase: Option<&str>,
) -> Result<LoadedWallet, String> {
    let old_kf = keyfile::read(&wallet.path).map_err(|e| e.to_string())?;

    let old_pass = old_passphrase.map(|p| SecretBytes::from_vec(p.as_bytes().to_vec()));

    let seed = old_kf.open(old_pass.as_ref()).map_err(|e| e.to_string())?;

    let new_pass = new_passphrase.map(|p| SecretBytes::from_vec(p.as_bytes().to_vec()));

    let iters = if new_pass.is_some() {
        plaine_wallet::kdf::DEFAULT_ITERS
    } else {
        0
    };

    let new_kf = KeyFile::seal(
        old_kf.role,
        plaine_wallet::now_secs(),
        &seed,
        new_pass.as_ref(),
        iters,
    )
    .map_err(|e| e.to_string())?;

    if new_kf.pubkey != old_kf.pubkey || new_kf.address != old_kf.address {
        return Err(
            "refusing passphrase change: the new key file does not reproduce the same wallet"
                .into(),
        );
    }

    replace_keyfile_atomically(&wallet.path, &new_kf, new_pass.as_ref())?;

    open_wallet(&wallet.path)
}

fn replace_keyfile_atomically(
    path: &Path,
    new_kf: &KeyFile,
    new_pass: Option<&SecretBytes>,
) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let name = path
        .file_name()
        .ok_or_else(|| "invalid wallet path".to_string())?
        .to_string_lossy();

    let tag = format!("{}-{}", std::process::id(), plaine_wallet::now_secs());

    let temp = parent.join(format!(".{name}.new-{tag}"));

    let old = parent.join(format!(".{name}.old-{tag}"));

    let _ = std::fs::remove_file(&temp);

    let _ = std::fs::remove_file(&old);

    keyfile::create_verified(&temp, new_kf, new_pass, &new_kf.pubkey).map_err(|e| e.to_string())?;

    std::fs::rename(path, &old).map_err(|e| {
        let _ = std::fs::remove_file(&temp);

        format!("cannot preserve existing wallet before replacement: {e}")
    })?;

    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::rename(&old, path);

        let _ = std::fs::remove_file(&temp);

        return Err(format!(
            "cannot install replacement wallet; original was restored: {e}"
        ));
    }

    // The temporary file was already write-then-verified by
    // keyfile::create_verified() before it replaced the original.
    // Re-opening it here would repeat the expensive KDF for no
    // additional safety.
    let _ = std::fs::remove_file(&old);

    Ok(())
}

pub fn make_secret_passphrase(passphrase: &str) -> SecretBytes {
    SecretBytes::from_vec(passphrase.as_bytes().to_vec())
}

pub fn verify_secret_passphrase(
    wallet: &LoadedWallet,
    passphrase: &SecretBytes,
) -> Result<(), String> {
    let kf = keyfile::read(&wallet.path).map_err(|e| e.to_string())?;

    kf.open(Some(passphrase)).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn backup_secret_session(
    wallet: &LoadedWallet,
    passphrase: Option<&SecretBytes>,
) -> Result<String, String> {
    let kf = keyfile::read(&wallet.path).map_err(|e| e.to_string())?;

    let seed = kf.open(passphrase).map_err(|e| e.to_string())?;

    Ok(plaine_wallet::sechex::encode_backup(&seed))
}

pub fn build_transfer_raw_session(
    wallet: &LoadedWallet,
    passphrase: Option<&SecretBytes>,
    to: &str,
    amount_mile: u128,
    fee_mile: u128,
    nonce: u64,
) -> Result<String, String> {
    use plaine_consensus::constants::Network;

    let kf = keyfile::read(&wallet.path).map_err(|e| e.to_string())?;

    let seed = kf.open(passphrase).map_err(|e| e.to_string())?;

    let tx = plaine_wallet::txbuild::build_transfer(
        Network::Main,
        &seed,
        to,
        amount_mile,
        fee_mile,
        nonce,
    )
    .map_err(|e| e.to_string())?;

    Ok(plaine_consensus::hex::encode(&tx.encode()))
}
