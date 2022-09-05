use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::fmt::Write;
use std::fmt::{Debug, Display};
use std::io::Write as _;

use tracing::field::Field;
use tracing::span::{Attributes, Record};
use tracing::{field, Event, Id, Level, Metadata, Subscriber};

use crate::log::datetime::DateTime;

pub struct Logger {
    level: Level,
    timestamp: bool,
}

impl Logger {
    pub fn new(level: Level, timestamp: bool) -> Self {
        Self { level, timestamp }
    }
}

impl Subscriber for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= self.level
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        panic!("trace is not supported")
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        thread_local! {
            static BUF: RefCell<String> = RefCell::new(String::new());
        }

        BUF.with(|buf| {
            let borrow = buf.try_borrow_mut();
            let mut a;
            let mut b;
            let mut buf = match borrow {
                Ok(buf) => {
                    a = buf;
                    &mut *a
                }
                _ => {
                    b = String::new();
                    &mut b
                }
            };

            let metadata = event.metadata();

            // write timestamp
            if self.timestamp {
                let date = DateTime::now();
                write!(&mut buf, "{} ", date).expect("write timestamp to log buffer failed");
            }

            // write level
            write!(&mut buf, "{:5} ", metadata.level()).expect("write level to log buffer failed");

            // write module
            if let Some(module) = metadata.module_path() {
                buf.push_str(module);
                buf.push(' ');
            }

            event.record(&mut Visitor { buf });

            buf.push('\n');

            let mut writer = std::io::stdout();
            writer
                .write(buf.as_bytes())
                .expect("write log to stdout failed");

            buf.clear();
        });
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Renders an error into a list of sources, *including* the error
struct ErrorSourceList<'a>(&'a (dyn std::error::Error + 'static));

impl<'a> Display for ErrorSourceList<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        let mut curr = Some(self.0);
        while let Some(curr_err) = curr {
            list.entry(&format_args!("{}", curr_err));
            curr = curr_err.source();
        }
        list.finish()
    }
}

struct Visitor<'a> {
    buf: &'a mut String,
}

impl<'a> field::Visit for Visitor<'a> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.record_debug(field, &format_args!("{}", value))
        } else {
            self.record_debug(field, &value)
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        if let Some(source) = value.source() {
            self.record_debug(
                field,
                &format_args!("{}, {}.sources: {}", value, field, ErrorSourceList(source)),
            )
        } else {
            self.record_debug(field, &format_args!("{}", value))
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        match field.name() {
            "message" => {
                write!(self.buf, "{:?}", value).expect("write message to log buffer failed");
            }
            name => {
                let name = if name.starts_with("r#") {
                    &name[2..]
                } else {
                    name
                };

                write!(self.buf, " {}={:?}", name, value)
                    .expect("write field to log buffer failed");
            }
        };
    }
}
