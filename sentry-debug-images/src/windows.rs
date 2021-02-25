use std::env;

use sentry_core::protocol::debugid::DebugId;
use sentry_core::protocol::{DebugImage, SymbolicDebugImage};
use sentry_core::types::Uuid;

use findshlibs::{SharedLibrary, SharedLibraryId, TargetSharedLibrary, TARGET_SUPPORTED};

pub fn debug_images() -> Vec<DebugImage> {
    let mut images = vec![];
    if !TARGET_SUPPORTED {
        return images;
    }

    TargetSharedLibrary::each(|shlib| {
        let maybe_debug_id = shlib.debug_id().and_then(|id| match id {
            SharedLibraryId::PdbSignature(mut signature, age) => {
                Some(DebugId::from_parts(
                    {
                        // PE always stores the signature with little endian UUID fields.
                        // Convert to network byte order (big endian) to match the
                        // Breakpad processor's expectations.
                        //let mut data = signature;
                        signature[0..4].reverse(); // uuid field 1
                        signature[4..6].reverse(); // uuid field 2
                        signature[6..8].reverse(); // uuid field 3
                        Uuid::from_bytes(signature)
                    },
                    age,
                ))
            }
            SharedLibraryId::Uuid(_)
            | SharedLibraryId::GnuBuildId(_)
            | SharedLibraryId::PeSignature(_, _) => {
                // should never happen
                None
            }
        });

        let debug_id = match maybe_debug_id {
            Some(debug_id) => debug_id,
            None => return,
        };

        let mut name = shlib.name().to_string_lossy().to_string();
        if name.is_empty() {
            name = env::current_exe()
                .map(|x| x.display().to_string())
                .unwrap_or_else(|_| "<main>".to_string());
        }

        images.push(
            SymbolicDebugImage {
                name,
                arch: None,
                image_addr: (shlib.virtual_memory_bias().0 as usize).into(),
                image_size: shlib.len() as u64,
                image_vmaddr: (shlib.virtual_memory_bias().0 as usize).into(),
                id: debug_id,
            }
            .into(),
        );
    });

    images
}
