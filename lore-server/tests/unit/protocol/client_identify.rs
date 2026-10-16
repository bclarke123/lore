// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::client_identify::*;
use lore_telemetry::user_agent_filter::USER_AGENT_UNKNOWN;
use lore_telemetry::user_agent_filter::UserAgentFilter;

mod parse {
    use super::*;

    #[test]
    fn valid_ascii_returns_some() {
        let ua = "my-client/1.0";
        let result = ClientIdentify::parse(Bytes::from(ua), true).unwrap();
        assert_eq!(
            result,
            ClientIdentify {
                user_agent: Some(ua.to_string()),
                is_trusted: true,
            }
        );
    }

    #[test]
    fn empty_bytes_returns_none() {
        let result = ClientIdentify::parse(Bytes::new(), true).unwrap();
        assert_eq!(
            result,
            ClientIdentify {
                user_agent: None,
                is_trusted: true,
            }
        );
    }

    #[test]
    fn exactly_256_bytes_returns_some() {
        let ua = "a".repeat(USER_AGENT_MAX_BYTES);
        let result = ClientIdentify::parse(Bytes::from(ua.clone()), true).unwrap();
        assert_eq!(
            result,
            ClientIdentify {
                user_agent: Some(ua),
                is_trusted: true,
            }
        );
    }

    #[test]
    fn over_256_bytes_returns_none() {
        let ua = "a".repeat(USER_AGENT_MAX_BYTES + 1);
        let result = ClientIdentify::parse(Bytes::from(ua), true).unwrap();
        assert_eq!(
            result,
            ClientIdentify {
                user_agent: None,
                is_trusted: true,
            }
        );
    }

    #[test]
    fn non_ascii_returns_none() {
        // Multi-byte UTF-8; not ASCII.
        let result = ClientIdentify::parse(Bytes::from("lore/1.0-\u{1F4E6}"), true).unwrap();
        assert_eq!(
            result,
            ClientIdentify {
                user_agent: None,
                is_trusted: true,
            }
        );
    }

    #[test]
    fn every_printable_ascii_byte_returns_some() {
        let ua: String = (0x20u8..=0x7E).map(char::from).collect();
        let result = ClientIdentify::parse(Bytes::from(ua.clone()), true).unwrap();
        assert_eq!(
            result,
            ClientIdentify {
                user_agent: Some(ua),
                is_trusted: true,
            }
        );
    }

    #[test]
    fn control_characters_return_none() {
        for byte in (0x00u8..=0x1F).chain(std::iter::once(0x7F)) {
            let raw = Bytes::from(vec![b'a', byte, b'b']);
            let result = ClientIdentify::parse(raw, true).unwrap();
            assert_eq!(
                result,
                ClientIdentify {
                    user_agent: None,
                    is_trusted: true,
                },
                "byte {byte:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn high_bit_bytes_return_none() {
        let result = ClientIdentify::parse(Bytes::from(vec![b'a', 0x80, b'b']), true).unwrap();
        assert_eq!(
            result,
            ClientIdentify {
                user_agent: None,
                is_trusted: true,
            }
        );
    }
}

mod apply {
    use super::*;

    #[test]
    fn none_is_noop() {
        let ci = ClientIdentify {
            user_agent: None,
            is_trusted: true,
        };
        let context = Arc::new(AttributeMap::default());
        let filter = UserAgentFilter::default();

        // Must not panic and must not insert anything.
        ci.apply(&context, &filter);
        assert!(context.get::<UserAgentValue>().is_none());
    }

    #[test]
    fn known_agent_stores_value_in_context() {
        let ci = ClientIdentify {
            user_agent: Some("my-client/1.0".to_string()),
            is_trusted: false,
        };
        let context = Arc::new(AttributeMap::default());
        // Default filter (no patterns) treats everything as known.
        let filter = UserAgentFilter::default();

        ci.apply(&context, &filter);

        let stored = context
            .get::<UserAgentValue>()
            .expect("UserAgentValue should be stored");
        assert_eq!(&*stored.0, "my-client/1.0");
    }

    #[test]
    fn unknown_agent_stores_unknown_sentinel() {
        let user_agent = "rogue-client/9.9".to_string();
        let untrusting = ClientIdentify {
            user_agent: Some(user_agent.clone()),
            is_trusted: false,
        };
        let trusting = ClientIdentify {
            user_agent: Some(user_agent.clone()),
            is_trusted: true,
        };
        let context = Arc::new(AttributeMap::default());
        // Allow-list that will not match "rogue-client".
        let filter = UserAgentFilter::new(&["my-client/.*"]).unwrap();

        untrusting.apply(&context, &filter);
        let stored = context
            .get::<UserAgentValue>()
            .expect("UserAgentValue should be stored");
        assert_eq!(&*stored.0, USER_AGENT_UNKNOWN);

        trusting.apply(&context, &filter);
        let stored = context
            .get::<UserAgentValue>()
            .expect("UserAgentValue should be stored");
        assert_eq!(&*stored.0, user_agent);
    }
}
