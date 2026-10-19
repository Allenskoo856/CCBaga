// [INPUT]: Win32 文件句柄安全描述符、进程 TokenUser/实际 TokenOwner SID 与迁移包相对成员名。
// [OUTPUT]: 已打开文件的本人所有权检查，以及拒绝 ADS/设备/Win32 别名的保守大小写碰撞键。
// [POS]: portable 的 Windows 信任边界；按句柄核所有者，不把路径前后检查当作句柄证明，不修改文件权限。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
use std::{
    fs,
    os::windows::io::AsRawHandle,
    path::{Component, Path},
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, IsValidSid, OWNER_SECURITY_INFORMATION,
    },
};

unsafe fn owned_sid(owner: *mut std::ffi::c_void) -> bool {
    !owner.is_null()
        && IsValidSid(owner) != 0
        && crate::windows::current_owner_sids()
            .iter()
            .any(|sid| EqualSid(owner, sid.as_ptr() as *mut _) != 0)
}

pub(super) fn owned_file(file: &fs::File) -> Result<(), String> {
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // ----- 描述符属于已持有句柄；目录项被替换也不能换掉被检查的对象 -----
    let owned = unsafe {
        let status = GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        let owned = status == 0 && owned_sid(owner);
        if !descriptor.is_null() {
            LocalFree(descriptor.cast());
        }
        owned
    };
    if owned {
        Ok(())
    } else {
        Err("迁移文件不属于当前用户或所有者无法核验。".into())
    }
}

pub(super) fn member_key(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    if text.is_empty() || text.len() > 4096 {
        return None;
    }
    let mut names = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else { return None; };
        let name = component.to_str()?;
        if name.ends_with(['.', ' '])
            || name.chars().any(|c| {
                c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            })
        {
            return None;
        }
        // Windows 设备名在带扩展名时仍保留；¹²³ 也是官方保留的设备数字。
        let stem = name.split('.').next()?.trim_end_matches(' ').to_uppercase();
        let device = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|number| {
                matches!(
                    number,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        if device {
            return None;
        }
        // ----- 保守 Unicode 大写允许误拒冲突名，不允许大小写别名分别落盘 -----
        names.push(name.to_uppercase());
    }
    if names.is_empty() {
        None
    } else {
        Some(names.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_reject_windows_special_names_and_aliases() {
        for name in [
            "data/0/file:stream",
            "data/0/NUL.txt",
            "data/0/con .txt",
            "data/0/COM1.log",
            "data/0/LPT³.txt",
            "data/0/CONIN$",
            "data/0/CONOUT$",
            "data/0/name.",
            "data/0/name ",
            "data/0/a?b",
            "data/0/a\u{7f}b",
            "../outside",
            "C:\\absolute",
            "\\\\server\\share\\file",
            "\\\\?\\C:\\device",
        ] {
            assert!(member_key(Path::new(name)).is_none(), "{name}");
        }
        assert_eq!(
            member_key(Path::new("data/0/Settings.json")),
            member_key(Path::new("DATA/0/settings.JSON"))
        );
        assert_eq!(
            member_key(Path::new("data/0/Σ.txt")),
            member_key(Path::new("data/0/ς.TXT"))
        );
        assert!(member_key(Path::new("data/0/中文 with spaces.json")).is_some());
        assert!(member_key(Path::new("data/0/normal.name.bagapack")).is_some());
    }

    #[test]
    fn opened_private_fixture_has_a_verified_owner() {
        let root = std::env::temp_dir().join(format!(
            "ccbaga-owner-{}",
            crate::identities::new_id().unwrap()
        ));
        crate::identities::private::directory(&root).unwrap();
        let path = root.join("fixture.bagapack");
        let file = crate::identities::private::create(&path).unwrap();
        owned_file(&file).unwrap();
        drop(file);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn missing_and_unrelated_owner_sids_are_rejected() {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        // Nobody SID 是合成比较输入；不修改任何实际文件或账号的所有者。
        let nobody: Vec<u16> = "S-1-0-0".encode_utf16().chain(Some(0)).collect();
        let mut sid = std::ptr::null_mut();
        unsafe {
            assert!(!owned_sid(std::ptr::null_mut()));
            assert_ne!(ConvertStringSidToSidW(nobody.as_ptr(), &mut sid), 0);
            let accepted = owned_sid(sid);
            LocalFree(sid.cast());
            assert!(!accepted);
        }
    }
}
