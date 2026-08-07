//! What a plugin manifest may declare it needs, and what this host actually
//! grants.
//!
//! `ARCHITECTURE.md` §6: "No declaration means no capability." v0.2 goes
//! further than that for two of the three capabilities — a declaration is not
//! enough either, because there is no host function to grant it through. A
//! plugin that asks for `network` or `active` is refused at load time rather
//! than silently downgraded to source-only, because a downgrade would let the
//! plugin's own manifest lie about what it does.

use serde::Deserialize;

use crate::error::PluginError;

/// Capabilities as written in `owlwarden.plugin.json`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestCapabilities {
    /// Needs to read project source. Always true in practice — v0.2 has no
    /// other kind of plugin — but written out so the manifest is honest about
    /// what it means, and so a future capability can be added beside it
    /// without changing the shape of this struct.
    #[serde(default)]
    pub source: bool,
    /// Needs the network. Declaring this refuses the plugin (see module docs).
    #[serde(default)]
    pub network: bool,
    /// Needs to make state-changing requests. Declaring this refuses the
    /// plugin for the same reason as `network`, and would additionally need
    /// `--allow-active` even if it were wired.
    #[serde(default)]
    pub active: bool,
}

impl ManifestCapabilities {
    /// Refuses a plugin that declares something this host does not wire.
    ///
    /// # Errors
    /// [`PluginError::UnsupportedCapability`] if `network` or `active` is set.
    pub fn ensure_supported(&self, plugin_id: &str) -> Result<(), PluginError> {
        if self.network {
            return Err(PluginError::UnsupportedCapability {
                id: plugin_id.to_owned(),
                capability: "network",
            });
        }
        if self.active {
            return Err(PluginError::UnsupportedCapability {
                id: plugin_id.to_owned(),
                capability: "active",
            });
        }
        Ok(())
    }

    /// The [`owlwarden_core::detector::Capabilities`] a loaded `WasmDetector`
    /// reports to the scheduler.
    ///
    /// Always `source_only()`: [`Self::ensure_supported`] has already
    /// rejected any manifest claiming otherwise, so this is not a second
    /// place that trust could leak in — it is a restatement of the same fact
    /// for the type the scheduler understands.
    #[must_use]
    pub fn to_core(self) -> owlwarden_core::detector::Capabilities {
        owlwarden_core::detector::Capabilities::source_only()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn source_only_is_accepted() {
        let caps = ManifestCapabilities {
            source: true,
            network: false,
            active: false,
        };
        assert!(caps.ensure_supported("demo").is_ok());
        assert_eq!(
            caps.to_core(),
            owlwarden_core::detector::Capabilities::source_only()
        );
    }

    #[test]
    fn network_is_refused_honestly_rather_than_downgraded() {
        let caps = ManifestCapabilities {
            source: true,
            network: true,
            active: false,
        };
        let error = caps.ensure_supported("demo").unwrap_err();
        assert!(matches!(
            error,
            PluginError::UnsupportedCapability {
                capability: "network",
                ..
            }
        ));
    }

    #[test]
    fn active_is_refused() {
        let caps = ManifestCapabilities {
            source: true,
            network: false,
            active: true,
        };
        let error = caps.ensure_supported("demo").unwrap_err();
        assert!(matches!(
            error,
            PluginError::UnsupportedCapability {
                capability: "active",
                ..
            }
        ));
    }
}
