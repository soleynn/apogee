//! Read-only resolution of the launch setup a profile will use.

/// Where a resolved setup value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Provenance {
    Profile,
    Host,
    Catalog,
    Prefix,
    Default,
}

/// One concrete launch-setup reading.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupValue {
    Runner {
        name: String,
        version: Option<String>,
    },
    Sync(apogee_runtime::SyncStatus),
    Gpu {
        selection: apogee_runtime::GpuSelect,
        identity: Option<String>,
    },
    Dxvk {
        version: Option<String>,
        nvapi: bool,
    },
    Dalamud {
        enabled: bool,
    },
}

/// A setup value paired with the authority that supplied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSetup {
    pub value: SetupValue,
    pub source: Provenance,
}
