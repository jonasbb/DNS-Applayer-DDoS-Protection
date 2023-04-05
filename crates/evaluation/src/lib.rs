use ipnetwork::IpNetwork;

#[allow(non_camel_case_types)]
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Location {
    // TODO provide a list of all possible locations
    xxx,
}

impl Location {
    pub fn logical_dsts() -> [&'static str; 1] {
        [
            // TODO list all combinations of locations and iprange_dst for which data files are available
            "xxx_198.51.100.1",
        ]
    }

    /// Return the best training length observed for each location
    pub fn best_train_length(&self) -> u8 {
        match self {
            Location::xxx => 24,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct DataConfiguration<A> {
    pub location: Location,
    pub iprange_dst: IpNetwork,
    pub window_start: u32,
    pub train_length: u8,
    pub test_length: u8,
    pub min_active: u8,
    pub min_pkts_avg: u32,
    pub low_pass: u32,
    pub above_train_limit: ordered_float::OrderedFloat<f64>,
    #[serde(skip, default, bound = "")]
    pub attacker: A,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct EvaluationResults {
    pub total: f64,
    pub true_positives: f64,
    pub true_negatives: f64,
    pub false_positives: f64,
    pub false_negatives: f64,
}

impl EvaluationResults {
    pub fn f1_score(&self) -> f64 {
        2. * self.true_positives
            / (2. * self.true_positives + self.false_positives + self.false_negatives)
    }

    pub fn fbeta_score(&self, beta: f64) -> f64 {
        let beta2 = beta.powi(2);

        (1.0 + beta2) * self.true_positives
            / ((1.0 + beta2) * self.true_positives
                + beta2 * self.false_positives
                + self.false_negatives)
    }

    pub fn normalize(&mut self) {
        self.true_positives /= self.total;
        self.true_negatives /= self.total;
        self.false_positives /= self.total;
        self.false_negatives /= self.total;
        self.total /= self.total;
    }

    pub fn balanced_accuracy(&self) -> f64 {
        // (TPR + TNR) / 2
        // TPR = TP / P
        // TNR = TN / N
        ((self.true_positives / (self.true_positives + self.false_negatives))
            + (self.true_negatives / (self.true_negatives + self.false_positives)))
            / 2.0
    }

    pub fn fpr(&self) -> f64 {
        self.false_positives / (self.false_positives + self.true_negatives)
    }

    pub fn fnr(&self) -> f64 {
        self.false_negatives / (self.false_negatives + self.true_positives)
    }
}

impl std::ops::Add for EvaluationResults {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self.total += rhs.total;
        self.true_positives += rhs.true_positives;
        self.true_negatives += rhs.true_negatives;
        self.false_positives += rhs.false_positives;
        self.false_negatives += rhs.false_negatives;
        self
    }
}

impl std::ops::AddAssign for EvaluationResults {
    fn add_assign(&mut self, rhs: Self) {
        self.total += rhs.total;
        self.true_positives += rhs.true_positives;
        self.true_negatives += rhs.true_negatives;
        self.false_positives += rhs.false_positives;
        self.false_negatives += rhs.false_negatives;
    }
}

#[derive(serde::Serialize)]
pub struct FlattenedPair<'a, A, B> {
    #[serde(flatten)]
    pub a: &'a A,
    #[serde(flatten)]
    pub b: &'a B,
}

pub fn ok<T>(t: T) -> color_eyre::eyre::Result<T> {
    Ok(t)
}
