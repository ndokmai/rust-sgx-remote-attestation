use ring::rand;

pub struct RandomState {
    inner: rand::SystemRandom,
}

impl RandomState {
    pub fn new() -> Self {
        Self { inner: rand::SystemRandom::new() }
    }

    pub fn inner(&self) -> &rand::SystemRandom {
        &self.inner
    }
}

