//! Conservative content sanity checks for PE image recovery.
//! These are advisory flags, never evidence that a page can be repaired or
//! safe grounds to discard potentially important forensic bytes.
use crate::rebuild::Pe;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutableTextProfile {
    pub utf16_ascii_pairs: usize,
    pub examined_pairs: usize,
}

impl ExecutableTextProfile {
    pub fn ratio(self) -> f64 {
        if self.examined_pairs == 0 { 0.0 }
        else { self.utf16_ascii_pairs as f64 / self.examined_pairs as f64 }
    }

    /// A high ratio of printable UTF-16LE text in an executable section is
    /// suspicious only in combination with independent PE table failures.
    pub fn strongly_text_like(self) -> bool {
        self.examined_pairs >= 2048 &&
        self.utf16_ascii_pairs.saturating_mul(10) >= self.examined_pairs.saturating_mul(6)
    }
}

pub fn executable_text_profile(pe: &Pe, file: &[u8]) -> ExecutableTextProfile {
    let mut profile = ExecutableTextProfile::default();
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 || section.raw_size == 0 {
            continue;
        }
        let Some(end) = section.raw_offset.checked_add(section.raw_size) else { continue };
        let Some(bytes) = file.get(section.raw_offset..end) else { continue };
        for pair in bytes.chunks_exact(2) {
            profile.examined_pairs += 1;
            if pair[1] == 0 && (pair[0] == b' ' || pair[0].is_ascii_graphic()) {
                profile.utf16_ascii_pairs += 1;
            }
        }
    }
    profile
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rebuild::Section;

    fn sample_pe() -> Pe {
        Pe { is_64: false, size_of_image: 0x3000, headers_size: 0x200,
            raw_file_size: 0x2200, sections: vec![Section {
                name: ".text".into(), virtual_address: 0x1000,
                virtual_size: 0x2000, raw_offset: 0x200, raw_size: 0x2000,
                characteristics: 0x6000_0020 }], import: (0, 0), export: (0, 0), resource: (0, 0), timestamp: 0, characteristics: 0, machine: 0x8664, entry_point: 0x1000 }
    }

    #[test]
    fn flags_long_utf16_text_in_executable_section() {
        let pe = sample_pe();
        let mut file = vec![0u8; pe.raw_file_size];
        for pair in file[0x200..].chunks_exact_mut(2) {
            pair.copy_from_slice(b"A\0");
        }
        let profile = executable_text_profile(&pe, &file);
        assert!(profile.strongly_text_like());
        assert_eq!(profile.ratio(), 1.0);
    }

    #[test]
    fn does_not_flag_ordinary_non_text_bytes() {
        let pe = sample_pe();
        let mut file = vec![0x90u8; pe.raw_file_size];
        file[0x200] = 0xc3;
        assert!(!executable_text_profile(&pe, &file).strongly_text_like());
    }
}
