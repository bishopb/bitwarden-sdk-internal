pub mod variant;

pub mod prelude {
    pub use crate::variant::ErrorVariant;
    pub use bitwarden_error_macro::*;
}