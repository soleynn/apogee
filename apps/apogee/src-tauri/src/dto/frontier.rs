//! Display-safe public service data returned by core.

use std::path::Path;

use apogee_core::{BannerData, FrontierData, GateData, NewsData, NewsRow};
use serde::Serialize;
use ts_rs::TS;

/// One response from a public display query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum FrontierDto {
    News(NewsDto),
    Gate(GateDto),
    Banners(Vec<BannerDto>),
    Unknown,
}

impl From<&FrontierData> for FrontierDto {
    fn from(data: &FrontierData) -> Self {
        match data {
            FrontierData::News(news) => Self::News(NewsDto::from(news)),
            FrontierData::Gate(gate) => Self::Gate(GateDto::from(gate)),
            FrontierData::Banners(banners) => {
                Self::Banners(banners.iter().map(BannerDto::from).collect())
            }
            _ => Self::Unknown,
        }
    }
}

/// Headline groups from the public launcher feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewsDto {
    news: Vec<NewsRowDto>,
    topics: Vec<NewsRowDto>,
    pinned: Vec<NewsRowDto>,
}

impl From<&NewsData> for NewsDto {
    fn from(data: &NewsData) -> Self {
        Self {
            news: data.news.iter().map(NewsRowDto::from).collect(),
            topics: data.topics.iter().map(NewsRowDto::from).collect(),
            pinned: data.pinned.iter().map(NewsRowDto::from).collect(),
        }
    }
}

/// One headline carrying only an opaque link id, never an upstream URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(super) struct NewsRowDto {
    id: String,
    date: String,
    title: String,
    tag: String,
}

impl From<&NewsRow> for NewsRowDto {
    fn from(row: &NewsRow) -> Self {
        Self {
            id: row.id.clone(),
            date: row.date.clone(),
            title: row.title.clone(),
            tag: row.tag.clone(),
        }
    }
}

/// Whether login is open and the messages supplied with that reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GateDto {
    open: bool,
    messages: Vec<String>,
    news: Vec<String>,
}

impl From<&GateData> for GateDto {
    fn from(data: &GateData) -> Self {
        Self {
            open: data.open,
            messages: data.messages.clone(),
            news: data.news.clone(),
        }
    }
}

/// One promotional row whose artwork is already a validated local asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BannerDto {
    id: String,
    artwork: Option<String>,
    order_priority: String,
    fix_order: Option<String>,
}

impl From<&BannerData> for BannerDto {
    fn from(row: &BannerData) -> Self {
        Self {
            id: row.id.clone(),
            artwork: row.artwork.as_deref().map(path_text),
            order_priority: row.order_priority.clone(),
            fix_order: row.fix_order.clone(),
        }
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn frontier_rows_cross_with_opaque_ids_and_local_artwork_only() {
        let data = FrontierData::Banners(vec![BannerData {
            id: "banner-7".to_owned(),
            artwork: Some(PathBuf::from("/cache/banner-7.png")),
            order_priority: "1".to_owned(),
            fix_order: Some("2".to_owned()),
        }]);

        assert_eq!(
            FrontierDto::from(&data),
            FrontierDto::Banners(vec![BannerDto {
                id: "banner-7".to_owned(),
                artwork: Some("/cache/banner-7.png".to_owned()),
                order_priority: "1".to_owned(),
                fix_order: Some("2".to_owned()),
            }])
        );
    }
}
