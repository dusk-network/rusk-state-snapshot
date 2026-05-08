use crate::retention::RetentionPolicy;
use chrono::{DateTime, Datelike, Duration, Months, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Daily,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub label: String,
    pub kind: TargetKind,
    pub period: String,
    pub cutoff: DateTime<Utc>,
}

pub fn desired_daily_targets(now: DateTime<Utc>, keep_daily: usize) -> Vec<Target> {
    if keep_daily == 0 {
        return Vec::new();
    }
    let today = now.date_naive();
    let first = today - Duration::days(keep_daily as i64);
    (0..keep_daily)
        .map(|i| {
            let day = first + Duration::days(i as i64);
            let cutoff = utc_midnight(day + Duration::days(1));
            let period = day.format("%Y-%m-%d").to_string();
            Target {
                label: format!("daily:{period}"),
                kind: TargetKind::Daily,
                period,
                cutoff,
            }
        })
        .collect()
}

pub fn desired_monthly_targets(now: DateTime<Utc>, keep_months: usize) -> Vec<Target> {
    if keep_months == 0 {
        return Vec::new();
    }
    let first_of_this_month = NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap();
    let first_month = first_of_this_month
        .checked_sub_months(Months::new(keep_months as u32))
        .unwrap();
    (0..keep_months)
        .map(|i| {
            let month = first_month
                .checked_add_months(Months::new(i as u32))
                .unwrap();
            let cutoff = utc_midnight(month.checked_add_months(Months::new(1)).unwrap());
            let period = month.format("%Y-%m").to_string();
            Target {
                label: format!("monthly:{period}"),
                kind: TargetKind::Monthly,
                period,
                cutoff,
            }
        })
        .collect()
}

pub fn desired_yearly_targets(
    now: DateTime<Utc>,
    keep_years: usize,
    genesis_time: Option<DateTime<Utc>>,
) -> Vec<Target> {
    let last_completed_year = now.year() - 1;
    let first_year = if keep_years == 0 {
        genesis_time
            .map(|t| t.year())
            .unwrap_or(last_completed_year)
    } else {
        last_completed_year - keep_years as i32 + 1
    };
    if first_year > last_completed_year {
        return Vec::new();
    }
    (first_year..=last_completed_year)
        .map(|year| {
            let cutoff = Utc
                .with_ymd_and_hms(year + 1, 1, 1, 0, 0, 0)
                .single()
                .unwrap();
            let period = year.to_string();
            Target {
                label: format!("yearly:{period}"),
                kind: TargetKind::Yearly,
                period,
                cutoff,
            }
        })
        .collect()
}

pub fn desired_targets(
    now: DateTime<Utc>,
    policy: &RetentionPolicy,
    genesis_time: Option<DateTime<Utc>>,
) -> Vec<Target> {
    let mut targets = Vec::new();
    targets.extend(desired_monthly_targets(now, policy.monthly.keep_months));
    targets.extend(desired_yearly_targets(
        now,
        policy.yearly.keep_years,
        genesis_time,
    ));
    targets.extend(desired_daily_targets(now, policy.rolling.keep_daily));
    targets.sort_by(|a, b| a.cutoff.cmp(&b.cutoff).then(a.label.cmp(&b.label)));
    targets
}

fn utc_midnight(date: NaiveDate) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(date.year(), date.month(), date.day(), 0, 0, 0)
        .single()
        .unwrap()
}
