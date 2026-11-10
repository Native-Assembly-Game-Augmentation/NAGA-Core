use std::sync::Arc;

use crate::{DiagnosticStore, FileDiagnosticStore, ServiceRegistry};

pub struct RuntimeContext {
    pub services: ServiceRegistry,
    pub diagnostics: Arc<dyn DiagnosticStore>
}

impl Default for RuntimeContext {
    fn default() -> Self {
        Self {
            services: ServiceRegistry::default(),
            diagnostics: Arc::new(FileDiagnosticStore)
        }
    }
}
