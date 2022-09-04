use std::collections::BTreeSet;
use std::num::ParseIntError;
use std::str::FromStr;
use std::time::Instant;

const MIN_YEAR: u32 = 1970;
const MAX_YEAR: u32 = 2099;

#[derive(Debug)]
pub enum Error {
    ParseInt(ParseIntError),

    ArgumentCount,

    InvalidStepRange(String),

    InvalidRange(String),

    InvalidMonthIndicator(String),

    InvalidDayOfWeekIndicator(String),
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Self::ParseInt(err)
    }
}

#[derive(Debug, PartialEq)]
enum Seconds {
    Ignore,
    All,
    Constrained(BTreeSet<u32>),
}

#[derive(Debug, PartialEq)]
enum Years {
    All,
    Unbound,
    Constrained(BTreeSet<u32>),
}

#[derive(Debug, PartialEq, Clone)]
enum TimeRange {
    All,
    Constrained(BTreeSet<u32>),
}

#[derive(PartialEq, Debug)]
pub struct Cron {
    #[cfg(feature = "serde")]
    text: String,

    seconds: Seconds,
    minutes: TimeRange,
    hours: TimeRange,
    days_of_month: TimeRange,
    months: TimeRange,
    days_of_week: TimeRange,
    years: Years,
}

impl FromStr for Cron {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields = s.split_whitespace().collect::<Vec<_>>();

        match fields.len() {
            5 => Ok(Self {
                #[cfg(feature = "serde")]
                text: s.to_owned(),

                seconds: Seconds::Ignore,
                minutes: parse_field(fields[0], 0, 59, false, false, false)?,
                hours: parse_field(fields[1], 0, 23, false, false, false)?,
                days_of_month: parse_field(fields[2], 1, 31, false, false, false)?,
                months: parse_field(fields[3], 1, 12, false, false, true)?,
                days_of_week: parse_field(fields[4], 1, 7, false, true, false)?,
                years: Years::Unbound,
            }),
            6 => Ok(Self {
                #[cfg(feature = "serde")]
                text: s.to_owned(),

                seconds: match parse_field(fields[0], 0, 59, true, false, false)? {
                    TimeRange::All => Seconds::All,
                    TimeRange::Constrained(set) => Seconds::Constrained(set),
                },
                minutes: parse_field(fields[1], 0, 59, true, false, false)?,
                hours: parse_field(fields[2], 0, 23, true, false, false)?,
                days_of_month: parse_field(fields[3], 1, 31, true, false, false)?,
                months: parse_field(fields[4], 1, 12, true, false, true)?,
                days_of_week: parse_field(fields[5], 1, 7, true, true, false)?,
                years: Years::All,
            }),
            7 => Ok(Self {
                #[cfg(feature = "serde")]
                text: s.to_owned(),

                seconds: match parse_field(fields[0], 0, 59, true, false, false)? {
                    TimeRange::All => Seconds::All,
                    TimeRange::Constrained(set) => Seconds::Constrained(set),
                },
                minutes: parse_field(fields[1], 0, 59, true, false, false)?,
                hours: parse_field(fields[2], 0, 23, true, false, false)?,
                days_of_month: parse_field(fields[3], 1, 31, true, false, false)?,
                months: parse_field(fields[4], 1, 12, true, false, true)?,
                days_of_week: parse_field(fields[5], 1, 7, true, true, false)?,
                years: match parse_field(fields[6], MIN_YEAR, MAX_YEAR, true, false, false)? {
                    TimeRange::All => Years::All,
                    TimeRange::Constrained(f) => Years::Constrained(f),
                },
            }),
            _ => Err(Error::ArgumentCount),
        }
    }
}

impl Cron {
    pub fn next(&self) -> Instant {
        let Cron {
            seconds,
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
            years,
            ..
        } = self;
    }

    fn years(&self) {
        match &self.years {
            Years::All => from_year,
        }
    }
}

fn parse_range(
    left_range: &str,
    right_range: &str,
    is_vixie: bool,
    is_dom: bool,
    is_dow: bool,
) -> Result<(u32, u32), Error> {
    let l = parse_time_unit(left_range, is_vixie, is_dom, is_dow)?;
    let r = parse_time_unit(right_range, is_vixie, is_dom, is_dow)?;
    Ok((l, r))
}

fn month(value: &str) -> Result<u32, Error> {
    match value.to_uppercase().as_ref() {
        "JAN" | "1" => Ok(1),
        "FEB" | "2" => Ok(2),
        "MAR" | "3" => Ok(3),
        "APR" | "4" => Ok(4),
        "MAY" | "5" => Ok(5),
        "JUN" | "6" => Ok(6),
        "JUL" | "7" => Ok(7),
        "AUG" | "8" => Ok(8),
        "SEP" | "9" => Ok(9),
        "OCT" | "10" => Ok(10),
        "NOV" | "11" => Ok(11),
        "DEC" | "12" => Ok(12),
        _ => Err(Error::InvalidMonthIndicator(value.into())),
    }
}

fn day_of_week(value: &str, is_vixie: bool) -> Result<u32, Error> {
    if is_vixie {
        match value.to_uppercase().as_ref() {
            "SUN" | "1" => Ok(1),
            "MON" | "2" => Ok(2),
            "TUE" | "3" => Ok(3),
            "WED" | "4" => Ok(4),
            "THU" | "5" => Ok(5),
            "FRI" | "6" => Ok(6),
            "SAT" | "7" => Ok(7),
            _ => Err(Error::InvalidDayOfWeekIndicator(value.into())),
        }
    } else {
        match value.to_uppercase().as_ref() {
            "SUN" | "0" | "7" => Ok(1),
            "MON" | "1" => Ok(2),
            "TUE" | "2" => Ok(3),
            "WED" | "3" => Ok(4),
            "THU" | "4" => Ok(5),
            "FRI" | "5" => Ok(6),
            "SAT" | "6" => Ok(7),
            _ => Err(Error::InvalidDayOfWeekIndicator(value.into())),
        }
    }
}

fn parse_time_unit(s: &str, is_vixie: bool, is_dom: bool, is_dow: bool) -> Result<u32, Error> {
    let num;
    if is_dom {
        num = month(s)?;
    } else if is_dow {
        num = day_of_week(s, is_vixie)?;
    } else {
        num = s.parse()?;
    }
    Ok(num)
}

fn parse_field(
    value: &str,
    min: u32,
    max: u32,
    is_vixie: bool,
    is_dow: bool,
    is_dom: bool,
) -> Result<TimeRange, Error> {
    let mut set = BTreeSet::<u32>::new();

    for v in value.split(',') {
        let mut step_iter = v.splitn(2, '/');
        let left_step = step_iter.next().unwrap();
        let right_step = step_iter.next();

        let mut dash_iter = left_step.splitn(2, '-');
        let left_dash = dash_iter.next().unwrap();
        let right_dash = dash_iter.next();

        match (left_dash, right_dash, right_step) {
            (left_range, Some(right_range), Some(step_value)) => {
                let (l, r) = parse_range(left_range, right_range, is_vixie, is_dom, is_dow)?;

                if l < min || l > max || r < min || r > max || l > r {
                    return Err(Error::InvalidRange(v.into()));
                }

                for i in (l..=r).step_by(step_value.parse()?) {
                    set.insert(i);
                }
            }
            (left_range, Some(right_range), None) => {
                let (l, r) = parse_range(left_range, right_range, is_vixie, is_dom, is_dow)?;

                if l < min || l > max || r < min || r > max || l > r {
                    return Err(Error::InvalidRange(v.into()));
                }

                if l == min && r == max {
                    return Ok(TimeRange::All);
                }

                for i in l..=r {
                    set.insert(i);
                }
            }
            (left_most, None, Some(step_value)) => match left_most {
                "*" => {
                    for i in (min..=max).step_by(step_value.parse()?) {
                        set.insert(i);
                    }
                }
                _ => {
                    let left = parse_time_unit(left_most, is_vixie, is_dom, is_dow)?;

                    for i in (left..=max).step_by(step_value.parse()?) {
                        set.insert(i);
                    }
                }
            },
            (left_most, None, None) => match left_most {
                "*" => {
                    return Ok(TimeRange::All);
                }
                _ => {
                    let i = parse_time_unit(left_most, is_vixie, is_dom, is_dow)?;
                    set.insert(i);
                }
            },
        };
    }

    Ok(TimeRange::Constrained(set))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_linux_crontab() {
        let expected = Cron {
            #[cfg(feature = "serde")]
            text: "*/5 * * * *".to_owned(),

            seconds: Seconds::Ignore,
            minutes: TimeRange::Constrained((0..=59).into_iter().step_by(5).collect()),
            hours: TimeRange::All,
            days_of_month: TimeRange::All,
            months: TimeRange::All,
            days_of_week: TimeRange::All,
            years: Years::Unbound,
        };
        let cron = Cron::from_str("*/5 * * * *").unwrap();
        assert_eq!(expected, cron);
    }
}
