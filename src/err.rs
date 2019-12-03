
#[derive(Debug)]
pub enum TrustChainErrorKind {
    ArtifactFolderReadError,
    ArtifactNotFound,
    ArtifactReadError,
    ClaimNotFound,
    Claims,
    ExpiredSignature,
    ExpiredKeySignature,
    Generic,
    Gpg,
    InvalidArtifactId,
    InvalidSignature,
    Io,
}

#[derive(Debug)]
pub struct TrustChainError {
    pub kind: TrustChainErrorKind,
    pub description: String,
}

#[macro_export]
macro_rules! err {
    ($kind: ident, $($args: tt)+) => (
        Err(TrustChainError {
            kind: crate::err::TrustChainErrorKind::$kind,
            description: format!($($args)*),
        })
    )
}

#[macro_export]
macro_rules! io_guarded {
    ($expr: expr, $kind: ident, $($args: tt)+) => (
        match $expr {
            Ok(x) => x,
            Err(e) => return err!($kind, "{} @ {:?}", format!($($args)*), e)
        }
    )
}

#[macro_export]
macro_rules! execute {
    ($kind: ident, $err_msg: expr, $command: expr $(,$arg: expr)*) => ({
        let mut mmm_command = std::process::Command::new($command);

        $(
            mmm_command.arg($arg);
        )*

        log::debug!("{:?}", &mmm_command);

//TODO differentiated error messages
        let mut mmm_process: std::process::Child = io_guarded!(mmm_command.spawn(), $kind, "{}", $err_msg);
        let mmm_sign_status = io_guarded!(mmm_process.wait(), $kind, "{}", $err_msg);

        if !mmm_sign_status.success() {
            return err!($kind, "{}", $err_msg);
        }
    })
}