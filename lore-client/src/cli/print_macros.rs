// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::LazyLock;

use anstream::Stderr;
use anstream::Stdout;
use parking_lot::Mutex;

#[doc(hidden)]
pub static ANSTREAM_STDOUT: LazyLock<Mutex<Stdout>> =
    LazyLock::new(|| Mutex::new(anstream::stdout()));
#[doc(hidden)]
pub static ANSTREAM_STDERR: LazyLock<Mutex<Stderr>> =
    LazyLock::new(|| Mutex::new(anstream::stderr()));

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _pb_suspend = $crate::progress_bar::suspend_current_progress_bar();
        if cfg!(feature = "test-util") {
            let mut target_stream = std::io::stdout();
            let buffer = anstream::_macros::to_adapted_string(
                &format_args!($($arg)*),
                &target_stream
            );
            let _ = ::std::write!(target_stream, "{}", buffer);
        } else {
            let mut stream_lock = $crate::print_macros::ANSTREAM_STDOUT.lock();
            let mut stream = $crate::pager::get_current_pager().with_backup_stream(
                &mut *stream_lock
            );
            let _ = ::std::write!(&mut stream, $($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _pb_suspend = $crate::progress_bar::suspend_current_progress_bar();
        if cfg!(feature = "test-util") {
            let mut target_stream = std::io::stdout();
            let buffer = anstream::_macros::to_adapted_string(
                &format_args!($($arg)*),
                &target_stream
            );
            let _ = ::std::writeln!(target_stream, "{}", buffer);
        } else {
            let mut stream_lock = $crate::print_macros::ANSTREAM_STDOUT.lock();
            let mut stream = $crate::pager::get_current_pager().with_backup_stream(
                &mut *stream_lock
            );
            let _ = ::std::writeln!(&mut stream, $($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _pb_suspend = $crate::progress_bar::suspend_current_progress_bar();
        if cfg!(feature = "test-util") {
            let mut target_stream = std::io::stderr();
            let buffer = anstream::_macros::to_adapted_string(
                &format_args!($($arg)*),
                &target_stream
            );
            let _ = ::std::write!(target_stream, "{}", buffer);
        } else {
            let mut stream_lock = $crate::print_macros::ANSTREAM_STDERR.lock();
            let mut stream = $crate::pager::get_current_pager().with_backup_stream(
                &mut *stream_lock
            );
            let _ = ::std::write!(&mut stream, $($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprintln {
    () => {
        eprint!("\n")
    };
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _pb_suspend = $crate::progress_bar::suspend_current_progress_bar();
        if cfg!(feature = "test-util") {
            let mut target_stream = std::io::stderr();
            let buffer = anstream::_macros::to_adapted_string(
                &format_args!($($arg)*),
                &target_stream
            );
            let _ = ::std::writeln!(target_stream, "{}", buffer);
        } else {
            let mut stream_lock = $crate::print_macros::ANSTREAM_STDERR.lock();
            let mut stream = $crate::pager::get_current_pager().with_backup_stream(
                &mut *stream_lock
            );
            let _ = ::std::writeln!(&mut stream, $($arg)*);
        }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! progress_bar_internal_print {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if cfg!(feature = "test-util") {
            let mut target_stream = std::io::stdout();
            let buffer = anstream::_macros::to_adapted_string(
                &format_args!($($arg)*),
                &target_stream
            );
            let _ = ::std::write!(target_stream, "{}", buffer);
        } else {
            let mut stream_lock = $crate::print_macros::ANSTREAM_STDOUT.lock();
            let stream = &mut *stream_lock;
            let _ = ::std::write!(stream, $($arg)*);
        }
    }};
}
