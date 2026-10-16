// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use lore_telemetry::LabelArray;
use lore_telemetry::observe::Observe;
use lore_telemetry::observe::ObserveOption;
use lore_telemetry::observe::ObserveResult;
use lore_telemetry::observe::observe_option;
use lore_telemetry::observe::observe_result;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;
use opentelemetry::metrics::SyncInstrument;
use thiserror::Error;

struct RecordedValues {
    measurement: Option<f64>,
    attributes: Option<LabelArray>,
}

struct TestInstrument {
    recorded: RwLock<RecordedValues>,
}

#[derive(Debug, Error, PartialEq)]
enum TestError {
    #[error("Something Bad")]
    SomethingBad,
}

impl SyncInstrument<f64> for TestInstrument {
    fn measure(&self, measurement: f64, attributes: &[KeyValue]) {
        let mut lock = self.recorded.write().unwrap();
        if lock.measurement.is_none() {
            lock.measurement = Some(measurement);
        }
        if lock.attributes.is_none() {
            let mut vec = LabelArray::new();
            vec.insert_many(0, attributes.iter().cloned());
            lock.attributes = Some(vec);
        }
    }
}

mod basic {
    use smallvec::smallvec;

    use super::*;

    async fn return_hello_world_with_delay(delay: u64) -> String {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        "hello world".to_string()
    }

    #[tokio::test]
    async fn can_observe_future_with_closure() {
        let recorded_values = RecordedValues {
            measurement: None,
            attributes: None,
        };
        let instrument = Arc::new(TestInstrument {
            recorded: recorded_values.into(),
        });

        let histogram = Histogram::new(instrument.clone());
        let base_labels = smallvec![KeyValue::new("Base", "Label")];

        let task = async { return_hello_world_with_delay(100).await };

        let some_local_var = Duration::from_millis(1);
        let observe_fn = move |_result: &String, elapsed: &Duration, labels: &mut LabelArray| {
            if *elapsed > some_local_var {
                labels.push(KeyValue::new("my-slow", true));
            }
        };
        let result = task.observe(histogram, base_labels, observe_fn).await;

        let read = instrument.recorded.read().unwrap();
        assert_eq!(
            read.attributes,
            Some(smallvec![
                KeyValue::new("Base", "Label"),
                KeyValue::new("my-slow", true)
            ])
        );

        // the future was timed
        assert!(read.measurement.is_some());

        // the output is correct
        assert_eq!(result.output, "hello world");
    }
}

mod result {

    use smallvec::smallvec;

    use super::*;

    fn observe_testerror<R>(
        result: &Result<R, TestError>,
        duration: &Duration,
        labels: &mut LabelArray,
    ) {
        observe_result(result, duration, labels);
        labels.push(KeyValue::new("hello-from", "custom"));
    }

    async fn return_hello_world_with_delay(delay: u64) -> Result<String, TestError> {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        Ok("hello world".to_string())
    }

    async fn return_error_with_delay(delay: u64) -> Result<String, TestError> {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        Err(TestError::SomethingBad)
    }

    #[tokio::test]
    async fn can_observe_success_no_callback() {
        let recorded_values = RecordedValues {
            measurement: None,
            attributes: None,
        };
        let instrument = Arc::new(TestInstrument {
            recorded: recorded_values.into(),
        });

        let histogram = Histogram::new(instrument.clone());
        let base_labels = smallvec![KeyValue::new("Base", "Label")];

        let task = async { return_hello_world_with_delay(100).await };

        let result = task.observe_result(histogram, base_labels).await;

        let read = instrument.recorded.read().unwrap();
        assert_eq!(
            read.attributes,
            Some(smallvec![
                KeyValue::new("Base", "Label"),
                KeyValue::new("success", true)
            ])
        );

        // the future was timed
        assert!(read.measurement.is_some());

        // the output is correct
        assert!(result.output.is_ok());
        assert_eq!(result.output.unwrap(), "hello world");
    }

    #[tokio::test]
    async fn can_observe_failure_no_callback() {
        let recorded_values = RecordedValues {
            measurement: None,
            attributes: None,
        };
        let instrument = Arc::new(TestInstrument {
            recorded: recorded_values.into(),
        });

        let histogram = Histogram::new(instrument.clone());
        let base_labels = smallvec![KeyValue::new("Base", "Label")];

        let task = async { return_error_with_delay(100).await };

        let result = task.observe_result(histogram, base_labels).await;

        let read = instrument.recorded.read().unwrap();
        assert_eq!(
            read.attributes,
            Some(smallvec![
                KeyValue::new("Base", "Label"),
                KeyValue::new("success", false)
            ])
        );

        // the future was timed
        assert!(read.measurement.is_some());

        // the output is correct
        assert!(result.output.is_err());
        assert_eq!(result.output.unwrap_err(), TestError::SomethingBad);
    }

    #[tokio::test]
    async fn can_observe_custom_callback() {
        let recorded_values = RecordedValues {
            measurement: None,
            attributes: None,
        };
        let instrument = Arc::new(TestInstrument {
            recorded: recorded_values.into(),
        });

        let histogram = Histogram::new(instrument.clone());
        let base_labels = smallvec![KeyValue::new("Base", "Label")];

        let task = async { return_error_with_delay(100).await };

        let result = task
            .observe(histogram, base_labels, observe_testerror)
            .await;

        let read = instrument.recorded.read().unwrap();
        assert_eq!(
            read.attributes,
            Some(smallvec![
                KeyValue::new("Base", "Label"),
                KeyValue::new("success", false),
                KeyValue::new("hello-from", "custom"),
            ])
        );

        // the future was timed
        assert!(read.measurement.is_some());

        // the output is correct
        assert!(result.output.is_err());
        assert_eq!(result.output.unwrap_err(), TestError::SomethingBad);
    }
}

mod option {

    use smallvec::smallvec;

    use super::*;

    fn observe_test_string(output: &Option<String>, duration: &Duration, labels: &mut LabelArray) {
        observe_option(output, duration, labels);
        labels.push(KeyValue::new("hello-from", "custom"));
    }

    async fn return_hello_world_with_delay(delay: u64) -> Option<String> {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        Some("hello world".to_string())
    }

    async fn return_none_with_delay(delay: u64) -> Option<String> {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        None
    }

    #[tokio::test]
    async fn can_observe_some_no_callback() {
        let recorded_values = RecordedValues {
            measurement: None,
            attributes: None,
        };
        let instrument = Arc::new(TestInstrument {
            recorded: recorded_values.into(),
        });

        let histogram = Histogram::new(instrument.clone());
        let base_labels = smallvec![KeyValue::new("Base", "Label")];

        let task = async { return_hello_world_with_delay(100).await };

        let result = task.observe_option(histogram, base_labels).await;

        let read = instrument.recorded.read().unwrap();
        assert_eq!(
            read.attributes,
            Some(smallvec![
                KeyValue::new("Base", "Label"),
                KeyValue::new("option", "some")
            ])
        );

        // the future was timed
        assert!(read.measurement.is_some());

        // the output is correct
        assert!(result.output.is_some());
        assert_eq!(result.output.unwrap(), "hello world");
    }

    #[tokio::test]
    async fn can_observe_none_no_callback() {
        let recorded_values = RecordedValues {
            measurement: None,
            attributes: None,
        };
        let instrument = Arc::new(TestInstrument {
            recorded: recorded_values.into(),
        });

        let histogram = Histogram::new(instrument.clone());
        let base_labels = smallvec![KeyValue::new("Base", "Label")];

        let task = async { return_none_with_delay(100).await };

        let result = task.observe_option(histogram, base_labels).await;

        let read = instrument.recorded.read().unwrap();
        assert_eq!(
            read.attributes,
            Some(smallvec![
                KeyValue::new("Base", "Label"),
                KeyValue::new("option", "none")
            ])
        );

        // the future was timed
        assert!(read.measurement.is_some());

        // the output is correct
        assert!(result.output.is_none());
    }

    #[tokio::test]
    async fn can_observe_with_callback() {
        let recorded_values = RecordedValues {
            measurement: None,
            attributes: None,
        };
        let instrument = Arc::new(TestInstrument {
            recorded: recorded_values.into(),
        });

        let histogram = Histogram::new(instrument.clone());
        let base_labels = smallvec![KeyValue::new("Base", "Label")];

        let task = async { return_none_with_delay(100).await };

        let result = task
            .observe(histogram, base_labels, observe_test_string)
            .await;

        let read = instrument.recorded.read().unwrap();
        assert_eq!(
            read.attributes,
            Some(smallvec![
                KeyValue::new("Base", "Label"),
                KeyValue::new("option", "none"),
                KeyValue::new("hello-from", "custom")
            ])
        );

        // the future was timed
        assert!(read.measurement.is_some());

        // the output is correct
        assert!(result.output.is_none());
    }
}
