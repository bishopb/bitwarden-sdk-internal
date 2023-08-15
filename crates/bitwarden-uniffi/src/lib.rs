uniffi::setup_scaffolding!();

use std::sync::Arc;

use async_lock::RwLock;
use bitwarden::{
    client::client_settings::ClientSettings,
    mobile::{crypto::InitCryptoRequest, kdf::PasswordHashRequest},
};

mod error;
pub mod vault;

use error::Result;
use vault::ClientVault;

#[derive(uniffi::Object)]
pub struct Client(RwLock<bitwarden::Client>);

#[derive(uniffi::Object)]
pub struct ClientKdf(Arc<Client>);

#[derive(uniffi::Object)]
pub struct ClientCrypto(Arc<Client>);

#[uniffi::export]
impl Client {
    /// Initialize a new instance of the SDK client
    #[uniffi::constructor]
    pub fn new(settings: Option<ClientSettings>) -> Arc<Self> {
        Arc::new(Self(RwLock::new(bitwarden::Client::new(settings))))
    }

    /// KDF operations
    pub fn kdf(self: Arc<Self>) -> Arc<ClientKdf> {
        Arc::new(ClientKdf(self))
    }

    /// Crypto operations
    pub fn crypto(self: Arc<Self>) -> Arc<ClientCrypto> {
        Arc::new(ClientCrypto(self))
    }

    /// Vault item operations
    pub fn vault(self: Arc<Self>) -> Arc<ClientVault> {
        Arc::new(ClientVault(self))
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }
}

#[uniffi::export]
impl ClientKdf {
    /// Hash the user password
    pub async fn hash_password(&self, req: PasswordHashRequest) -> Result<String> {
        Ok(self.0 .0.read().await.kdf().hash_password(req).await?)
    }
}
#[uniffi::export]
impl ClientCrypto {
    /// Initialization method for the crypto. Needs to be called before any other crypto operations.
    pub async fn initialize_crypto(&self, req: InitCryptoRequest) -> Result<()> {
        Ok(self
            .0
             .0
            .write()
            .await
            .crypto()
            .initialize_crypto(req)
            .await?)
    }
}