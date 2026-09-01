use crate::types::BusError;

/// §7.7: "Depth limit 4 (inherited +1 per spawn). Fan-out ≤8 direct children per
/// session, ≤32 live sessions per team."
pub const MAX_DEPTH: u8 = 4;
pub const MAX_FAN_OUT: u32 = 8;
pub const MAX_TEAM_SIZE: u32 = 32;

/// `depth` is the depth the *child* would have (parent depth + 1). Called before the
/// child session is created.
pub fn check_depth(depth: u8) -> Result<(), BusError> {
    if depth > MAX_DEPTH {
        return Err(BusError::DepthLimitExceeded {
            depth,
            max: MAX_DEPTH,
        });
    }
    Ok(())
}

/// `count` is the parent's direct-child count *after* this spawn would succeed.
pub fn check_fan_out(count: u32) -> Result<(), BusError> {
    if count > MAX_FAN_OUT {
        return Err(BusError::FanOutLimitExceeded {
            count,
            max: MAX_FAN_OUT,
        });
    }
    Ok(())
}

/// `count` is the team's live-member count *after* this join would succeed.
pub fn check_team_size(count: u32) -> Result<(), BusError> {
    if count > MAX_TEAM_SIZE {
        return Err(BusError::TeamSizeLimitExceeded {
            count,
            max: MAX_TEAM_SIZE,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_limit_is_four() {
        assert!(check_depth(4).is_ok());
        let err = check_depth(5).unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::DepthLimitExceeded { depth: 5, max: 4 }
        ));
    }

    #[test]
    fn fan_out_limit_is_eight_direct_children() {
        assert!(check_fan_out(8).is_ok());
        let err = check_fan_out(9).unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::FanOutLimitExceeded { count: 9, max: 8 }
        ));
    }

    #[test]
    fn team_size_limit_is_thirty_two() {
        assert!(check_team_size(32).is_ok());
        let err = check_team_size(33).unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::TeamSizeLimitExceeded { count: 33, max: 32 }
        ));
    }
}
