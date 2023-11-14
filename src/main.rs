use base64::Engine;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use hex::FromHex;
use structopt::StructOpt;

use rudolfs::{Cache, LocalServerBuilder, S3ServerBuilder};

// Additional help to append to the end when `--help` is specified.
static AFTER_HELP: &str = include_str!("help.md");

#[derive(StructOpt)]
#[structopt(after_help = AFTER_HELP)]
struct Args {
    #[structopt(flatten)]
    global: GlobalArgs,

    #[structopt(subcommand)]
    backend: Backend,
}

#[derive(StructOpt)]
enum Backend {
    /// Starts the server with S3 as the storage backend.
    #[structopt(name = "s3")]
    S3(S3Args),

    /// Starts the server with the local disk as the storage backend.
    #[structopt(name = "local")]
    Local(LocalArgs),
}

#[derive(StructOpt)]
struct GlobalArgs {
    /// The host or address to listen on. If this is not specified, then
    /// `0.0.0.0` is used where the port can be specified with `--port`
    /// (port 8080 is used by default if that is also not specified).
    #[structopt(long = "host", env = "RUDOLFS_HOST")]
    host: Option<String>,

    /// The port to bind to. This is only used if `--host` is not specified.
    #[structopt(long = "port", default_value = "8080", env = "PORT")]
    port: u16,

    /// Encryption key to use.
    #[structopt(
    long = "key",
    parse(try_from_str = FromHex::from_hex),
    env = "RUDOLFS_KEY"
    )]
    key: [u8; 32],

    /// The hex-formatted secret key to use for edit-access restriction, if
    /// any. If not specified, no authentication will be used.
    /// Downloading is always allowed unauthenticated.
    #[structopt(
    long = "auth-key",
    env = "RUDOLFS_AUTH_KEY",
    parse(try_from_str = try_parse_base64)
    )]
    auth_key: Option<[u8; 32]>,

    /// Root directory of the object cache. If not specified or if the local
    /// disk is the storage backend, then no local disk cache will be used.
    #[structopt(long = "cache-dir", env = "RUDOLFS_CACHE_DIR")]
    cache_dir: Option<PathBuf>,

    /// Maximum size of the cache, in bytes. Set to 0 for an unlimited cache
    /// size.
    #[structopt(
        long = "max-cache-size",
        default_value = "50 GiB",
        env = "RUDOLFS_MAX_CACHE_SIZE"
    )]
    max_cache_size: human_size::Size,

    /// Logging level to use.
    #[structopt(
        long = "log-level",
        default_value = "info",
        env = "RUDOLFS_LOG"
    )]
    log_level: log::LevelFilter,
}

#[derive(StructOpt)]
struct S3Args {
    /// Amazon S3 bucket to use.
    #[structopt(long, env = "RUDOLFS_S3_BUCKET")]
    bucket: String,

    /// Amazon S3 path prefix to use.
    #[structopt(long, default_value = "lfs", env = "RUDOLFS_S3_PREFIX")]
    prefix: String,

    /// The base URL of your CDN. If specified, then all download URLs will be
    /// prefixed with this URL.
    #[structopt(long = "cdn", env = "RUDOLFS_S3_CDN")]
    cdn: Option<String>,
}

#[derive(StructOpt)]
struct LocalArgs {
    /// Directory where the LFS files should be stored. This directory will be
    /// created if it does not exist.
    #[structopt(long, env = "RUDOLFS_LOCAL_PATH")]
    path: PathBuf,
}

impl Args {
    async fn main(self) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize logging.
        let mut logger_builder = pretty_env_logger::formatted_timed_builder();
        logger_builder.filter_module("rudolfs", self.global.log_level);

        if let Ok(env) = std::env::var("RUST_LOG") {
            // Support the addition of RUST_LOG to help with debugging
            // dependencies, such as Hyper.
            logger_builder.parse_filters(&env);
        }

        logger_builder.init();

        // Find a socket address to bind to. This will resolve domain names.
        let addr = match self.global.host {
            Some(ref host) => host
                .to_socket_addrs()?
                .next()
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080))),
            None => SocketAddr::from(([0, 0, 0, 0], self.global.port)),
        };

        if self.global.auth_key.is_some() {
            log::info!(
                "Restricting mutation to authorized users using tokens."
            );
        } else {
            log::info!(
                "Allowing unauthenticated mutation, only use in a secure \
                 environment."
            );
        }

        log::info!("Initializing storage...");

        match self.backend {
            Backend::S3(s3) => s3.run(addr, self.global).await?,
            Backend::Local(local) => local.run(addr, self.global).await?,
        }

        Ok(())
    }
}

impl S3Args {
    async fn run(
        self,
        addr: SocketAddr,
        global_args: GlobalArgs,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = S3ServerBuilder::new(self.bucket, global_args.key);
        builder.prefix(self.prefix);

        if let Some(cdn) = self.cdn {
            builder.cdn(cdn);
        }

        if let Some(cache_dir) = global_args.cache_dir {
            let max_cache_size = global_args
                .max_cache_size
                .into::<human_size::Byte>()
                .value() as u64;
            builder.cache(Cache::new(cache_dir, max_cache_size));
        }

        builder.run(addr, global_args.auth_key).await
    }
}

impl LocalArgs {
    async fn run(
        self,
        addr: SocketAddr,
        global_args: GlobalArgs,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = LocalServerBuilder::new(self.path, global_args.key);

        if let Some(cache_dir) = global_args.cache_dir {
            let max_cache_size = global_args
                .max_cache_size
                .into::<human_size::Byte>()
                .value() as u64;
            builder.cache(Cache::new(cache_dir, max_cache_size));
        }

        builder.run(addr, global_args.auth_key).await
    }
}

fn try_parse_base64(inp: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let decoded = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::default(),
    )
    .decode(inp)?;
    decoded[..]
        .try_into()
        .map_err(|_| "Auth key must be 256 base64-encoded bits".into())
}

#[tokio::main]
async fn main() {
    let exit_code = if let Err(err) = Args::from_args().main().await {
        log::error!("{}", err);
        1
    } else {
        0
    };

    std::process::exit(exit_code);
}
