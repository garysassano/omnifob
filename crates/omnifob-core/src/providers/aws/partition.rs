//! AWS partitions: which one a Region or an ARN belongs to, and the hosts
//! each one signs in to the console at.
//!
//! Only the four partitions with a public console (and with cross-partition
//! STS federation) are represented. The isolated partitions (`aws-iso`,
//! `aws-iso-b`, `aws-iso-e`, `aws-iso-f`) are recognised and refused with a
//! message that names them.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, bail};

/// An AWS partition omnifob can open the console of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Partition {
    /// `aws`, the commercial Regions.
    Aws,
    /// `aws-cn`, the China Regions.
    China,
    /// `aws-us-gov`, AWS GovCloud (US).
    UsGov,
    /// `aws-eusc`, the AWS European Sovereign Cloud.
    EuropeanSovereign,
}

/// The Regions whose sign-in and console hosts carry no Region prefix. The
/// European Sovereign Cloud has none: `signin.amazonaws-eusc.eu` does not
/// resolve.
const UNPREFIXED_REGIONS: [&str; 3] = ["us-east-1", "us-gov-west-1", "cn-north-1"];

impl Partition {
    pub const ALL: [Self; 4] = [Self::Aws, Self::China, Self::UsGov, Self::EuropeanSovereign];

    /// The partition's name in ARNs (`arn:<name>:...`).
    pub fn arn_name(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::China => "aws-cn",
            Self::UsGov => "aws-us-gov",
            Self::EuropeanSovereign => "aws-eusc",
        }
    }

    /// The partition named `name` in ARNs.
    pub fn from_arn_name(name: &str) -> anyhow::Result<Self> {
        if let Some(found) = Self::ALL.into_iter().find(|p| p.arn_name() == name) {
            return Ok(found);
        }
        if name.starts_with("aws-iso") {
            bail!(
                "{name} is an isolated AWS partition, with no public console or cross-partition access"
            );
        }
        bail!("unknown AWS partition '{name}'")
    }

    /// The partition a Region belongs to, from its prefix. A Region with an
    /// unknown prefix is taken to be commercial, as new commercial
    /// geographies keep appearing. A name not shaped like a Region is
    /// refused, since Regions become part of host names.
    pub fn of_region(region: &str) -> anyhow::Result<Self> {
        check_region_name(region)?;
        if let Some(isolated) = isolated_partition(region) {
            bail!(
                "{region} is in {isolated}, an isolated AWS partition with no public console or cross-partition access"
            );
        }
        Ok(if region.starts_with("cn-") {
            Self::China
        } else if region.starts_with("us-gov-") {
            Self::UsGov
        } else if region.starts_with("eusc-") {
            Self::EuropeanSovereign
        } else {
            Self::Aws
        })
    }

    /// The partition an ARN names (`arn:aws-us-gov:iam::...` is GovCloud).
    pub fn of_arn(arn: &str) -> anyhow::Result<Self> {
        let mut fields = arn.split(':');
        let partition = match (fields.next(), fields.next()) {
            (Some("arn"), Some(partition)) if fields.next().is_some() => partition,
            _ => bail!("'{arn}' is not an ARN"),
        };
        Self::from_arn_name(partition).with_context(|| format!("in {arn}"))
    }

    /// Whether `region` is one of this partition's Regions.
    pub fn contains(self, region: &str) -> bool {
        Self::of_region(region).is_ok_and(|p| p == self)
    }

    /// Fails unless `region` is one of this partition's Regions.
    pub fn check_region(self, region: &str) -> anyhow::Result<()> {
        let other = Self::of_region(region)?;
        if other != self {
            bail!(
                "{region} is in the {} partition, not {}",
                other.arn_name(),
                self.arn_name()
            );
        }
        Ok(())
    }

    /// The Region served by the partition's unprefixed sign-in and console
    /// hosts; the European Sovereign Cloud has none.
    pub fn unprefixed_region(self) -> Option<&'static str> {
        match self {
            Self::EuropeanSovereign => None,
            _ => Some(self.default_region()),
        }
    }

    /// The partition's first Region: the one with the unprefixed hosts, or
    /// the European Sovereign Cloud's only Region.
    pub fn default_region(self) -> &'static str {
        match self {
            Self::Aws => "us-east-1",
            Self::China => "cn-north-1",
            Self::UsGov => "us-gov-west-1",
            Self::EuropeanSovereign => "eusc-de-east-1",
        }
    }

    /// STS's regional host in `region`. Fails for a name not shaped like a
    /// Region.
    pub fn sts_host(self, region: &str) -> anyhow::Result<String> {
        check_region_name(region)?;
        let domain = match self {
            Self::Aws | Self::UsGov => "amazonaws.com",
            Self::China => "amazonaws.com.cn",
            Self::EuropeanSovereign => "amazonaws.eu",
        };
        Ok(format!("sts.{region}.{domain}"))
    }

    /// The sign-in host for federation in `region`, regional as AWS
    /// recommends; a few Regions use the unprefixed host. Fails for a name
    /// not shaped like a Region, which could otherwise name another host.
    pub fn signin_host(self, region: &str) -> anyhow::Result<String> {
        let domain = match self {
            Self::Aws => "signin.aws.amazon.com",
            Self::China => "signin.amazonaws.cn",
            Self::UsGov => "signin.amazonaws-us-gov.com",
            Self::EuropeanSovereign => "signin.amazonaws-eusc.eu",
        };
        Ok(format!("{}{domain}", region_prefix(region)?))
    }

    /// The console host, for `region` or (with none) the partition's
    /// unprefixed one, which every partition has. Fails for a name not
    /// shaped like a Region.
    pub fn console_host(self, region: Option<&str>) -> anyhow::Result<String> {
        let domain = match self {
            Self::Aws => "console.aws.amazon.com",
            Self::China => "console.amazonaws.cn",
            Self::UsGov => "console.amazonaws-us-gov.com",
            Self::EuropeanSovereign => "console.amazonaws-eusc.eu",
        };
        let prefix = match region {
            Some(region) => region_prefix(region)?,
            None => String::new(),
        };
        Ok(format!("{prefix}{domain}"))
    }
}

impl fmt::Display for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.arn_name())
    }
}

impl FromStr for Partition {
    type Err = anyhow::Error;

    fn from_str(name: &str) -> anyhow::Result<Self> {
        Self::from_arn_name(name)
    }
}

fn region_prefix(region: &str) -> anyhow::Result<String> {
    check_region_name(region)?;
    Ok(if UNPREFIXED_REGIONS.contains(&region) {
        String::new()
    } else {
        format!("{region}.")
    })
}

/// Whether `name` is shaped like an AWS Region: lowercase words joined by
/// hyphens and ending in a number (`eu-west-1`, `us-gov-west-1`,
/// `eusc-de-east-1`, `us-isob-east-1`).
fn is_region_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('-').collect();
    let Some((number, words)) = parts.split_last() else {
        return false;
    };
    name.len() <= 32
        && words.len() >= 2
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
        && words
            .iter()
            .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()))
}

/// Fails unless `name` is shaped like an AWS Region. Regions become part of
/// sign-in and console host names, so anything else could send credentials
/// to another host. Unlike [`Partition::of_region`], it accepts the isolated
/// partitions' Regions: it checks the shape of the name only.
pub fn check_region_name(name: &str) -> anyhow::Result<()> {
    if !is_region_name(name) {
        bail!("'{name}' is not an AWS Region name (such as eu-west-1)");
    }
    Ok(())
}

/// The isolated partition a Region is in, if any: `us-iso-east-1` is in
/// `aws-iso`, `us-isob-east-1` in `aws-iso-b`, `eu-isoe-west-1` in
/// `aws-iso-e`, `us-isof-south-1` in `aws-iso-f`.
fn isolated_partition(region: &str) -> Option<String> {
    let letter = region.split('-').nth(1)?.strip_prefix("iso")?;
    Some(if letter.is_empty() {
        "aws-iso".to_string()
    } else {
        format!("aws-iso-{letter}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_map_to_partitions() {
        for (region, partition) in [
            ("us-east-1", Partition::Aws),
            ("eu-west-1", Partition::Aws),
            ("cn-north-1", Partition::China),
            ("cn-northwest-1", Partition::China),
            ("us-gov-west-1", Partition::UsGov),
            ("us-gov-east-1", Partition::UsGov),
            ("eusc-de-east-1", Partition::EuropeanSovereign),
        ] {
            assert_eq!(Partition::of_region(region).unwrap(), partition, "{region}");
            assert!(partition.contains(region), "{region}");
        }
        assert!(!Partition::Aws.contains("us-gov-west-1"));
        assert!(!Partition::UsGov.contains("us-isob-east-1"));
    }

    #[test]
    fn isolated_regions_are_refused_by_name() {
        for (region, name) in [
            ("us-iso-east-1", "aws-iso"),
            ("us-isob-east-1", "aws-iso-b"),
            ("eu-isoe-west-1", "aws-iso-e"),
            ("us-isof-south-1", "aws-iso-f"),
        ] {
            let error = Partition::of_region(region).unwrap_err().to_string();
            assert!(error.contains(name), "{error}");
            let error = Partition::from_arn_name(name).unwrap_err().to_string();
            assert!(error.contains("isolated"), "{error}");
        }
    }

    #[test]
    fn arn_names_round_trip() {
        for partition in Partition::ALL {
            assert_eq!(
                partition.arn_name().parse::<Partition>().unwrap(),
                partition
            );
            assert_eq!(partition.to_string(), partition.arn_name());
            assert!(partition.contains(partition.default_region()));
            if let Some(region) = partition.unprefixed_region() {
                assert_eq!(region, partition.default_region());
                assert!(!partition.signin_host(region).unwrap().starts_with(region));
            }
        }
        assert_eq!(Partition::EuropeanSovereign.unprefixed_region(), None);
        assert!(Partition::from_arn_name("aws-mars").is_err());
    }

    #[test]
    fn arns_name_their_partition() {
        assert_eq!(
            Partition::of_arn("arn:aws:iam::222222222222:role/path/Deploy").unwrap(),
            Partition::Aws
        );
        assert_eq!(
            Partition::of_arn("arn:aws-us-gov:iam::222222222222:role/Audit").unwrap(),
            Partition::UsGov
        );
        assert_eq!(
            Partition::of_arn("arn:aws-cn:iam::222222222222:role/R").unwrap(),
            Partition::China
        );
        assert_eq!(
            Partition::of_arn("arn:aws-eusc:iam::222222222222:role/R").unwrap(),
            Partition::EuropeanSovereign
        );
        let isolated = Partition::of_arn("arn:aws-iso-e:iam::2:role/R").unwrap_err();
        assert!(format!("{isolated:#}").contains("isolated"), "{isolated:#}");
        assert!(Partition::of_arn("Deploy").is_err());
        assert!(Partition::of_arn("arn:aws").is_err());
    }

    #[test]
    fn region_names_must_look_like_regions() {
        for region in [
            "us-east-1",
            "us-gov-west-1",
            "cn-northwest-1",
            "eusc-de-east-1",
            "eu-isoe-west-1",
            "us-isob-east-1",
            "ap-southeast-7",
            "mx-central-1",
            "il-central-1",
            "ca-west-1",
        ] {
            assert!(is_region_name(region), "{region}");
            assert!(Partition::ALL.iter().any(|p| p.signin_host(region).is_ok()));
        }
        for region in [
            "",
            "attacker.example#",
            "attacker.example/x",
            "evil.com#eu-west-1",
            "eu-west-1.attacker.example",
            "eu-west-1#",
            "eu-west-1/",
            "EU-WEST-1",
            "eu-west",
            "west-1",
            "eu--west-1",
            "eu-west-1a",
            "eu-west-",
            "-eu-west-1",
            "eu_west_1",
            "eu-west-1 ",
            "eu-wést-1",
            "eu-west-1:443",
            "eu-west-1@x",
            "x@eu-west-1",
            "aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-1",
        ] {
            assert!(!is_region_name(region), "{region:?}");
            assert!(Partition::of_region(region).is_err(), "{region:?}");
            assert!(Partition::Aws.check_region(region).is_err(), "{region:?}");
            assert!(!Partition::Aws.contains(region), "{region:?}");
            assert!(Partition::Aws.signin_host(region).is_err(), "{region:?}");
            assert!(
                Partition::Aws.console_host(Some(region)).is_err(),
                "{region:?}"
            );
        }
    }

    #[test]
    fn regions_are_checked_against_a_partition() {
        assert!(Partition::UsGov.check_region("us-gov-east-1").is_ok());
        let error = Partition::UsGov.check_region("eu-west-1").unwrap_err();
        assert_eq!(
            error.to_string(),
            "eu-west-1 is in the aws partition, not aws-us-gov"
        );
    }
}
