#![forbid(unsafe_code)]

use roundhouse_proto::ApiVersion;

pub fn negotiated_api_version() -> ApiVersion {
    ApiVersion::CURRENT
}
