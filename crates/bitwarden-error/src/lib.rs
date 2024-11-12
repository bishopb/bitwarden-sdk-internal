pub mod basic_error;
pub mod flat_error;

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod prelude {
    pub use crate::basic_error;
    pub use crate::flat_error::FlatError;
    pub use bitwarden_error_macro::*;

    #[cfg(feature = "wasm")]
    pub use {crate::wasm::SdkJsError, wasm_bindgen::prelude::*};
}