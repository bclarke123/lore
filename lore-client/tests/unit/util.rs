// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
mod format_bytes_tests {
    use lore_client::util::format_bytes_to_string;

    /// A count of bytes is exact, so a decimal on it is noise at best and
    /// misleading at worst — "600.00 bytes" reads as a measurement that was
    /// rounded when it was not.
    #[test]
    fn a_raw_byte_count_carries_no_decimals() {
        assert_eq!(format_bytes_to_string(0), "0 bytes");
        assert_eq!(format_bytes_to_string(1), "1 bytes");
        assert_eq!(format_bytes_to_string(600), "600 bytes");
        assert_eq!(format_bytes_to_string(1024), "1024 bytes");
    }

    #[test]
    fn a_scaled_unit_carries_decimals_because_the_remainder_means_something() {
        assert_eq!(format_bytes_to_string(1025), "1.00 KiB");
        assert_eq!(format_bytes_to_string(1536), "1.50 KiB");
        assert_eq!(format_bytes_to_string(3 * 1024 * 1024 / 2), "1.50 MiB");
        assert_eq!(
            format_bytes_to_string(3 * 1024 * 1024 * 1024 / 2),
            "1.50 GiB"
        );
    }
}

mod termination_signal_tests {
    use std::time::Duration;

    use lore_client::util::TerminationSignals;

    /// What registering ahead of the socket relies on: the handler is what holds
    /// a signal, so one delivered between registering and waiting reaches the
    /// wait rather than ending the process.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_signal_delivered_before_the_wait_still_ends_it() {
        let mut signals = TerminationSignals::register().expect("the handlers must register");

        // Safety: raises a signal in this process, which the handler registered
        // above now holds rather than the default disposition that would end it.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);

        tokio::time::timeout(Duration::from_secs(5), signals.recv())
            .await
            .expect("a signal delivered before the wait must still end it");
    }
}
