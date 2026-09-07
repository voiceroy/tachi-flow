use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;

use crate::model::{Side, SwapStatus};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no liquidity for {side:?} {amount_sats} sats")]
    NoLiquidity { side: Side, amount_sats: u64 },
    #[error("quote not found")]
    QuoteNotFound,
    #[error("quote expired")]
    QuoteExpired,
    #[error("swap not found")]
    SwapNotFound,
    #[error("invalid transition {from:?} -> {to:?}")]
    BadTransition { from: SwapStatus, to: SwapStatus },
    #[error("this action does not apply to {0:?} swaps")]
    WrongSide(Side),
    #[error("amount must be at least {0} sats")]
    AmountTooSmall(u64),
    #[error("{0}")]
    Invalid(String),
    #[error("bitcoin: {0}")]
    Bitcoin(String),
    #[error("tachi rpc: {0}")]
    Tachi(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NoLiquidity { .. } => StatusCode::CONFLICT,
            Self::QuoteNotFound | Self::SwapNotFound => StatusCode::NOT_FOUND,
            Self::QuoteExpired | Self::BadTransition { .. } | Self::WrongSide(_) => {
                StatusCode::CONFLICT
            }
            Self::AmountTooSmall(_) | Self::Invalid(_) | Self::Bitcoin(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Tachi(_) => StatusCode::BAD_GATEWAY,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: self.to_string(),
        })
    }
}


