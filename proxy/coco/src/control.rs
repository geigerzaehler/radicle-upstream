//! Utility for fixture data in the monorepo.

use std::{convert::TryFrom, env, io, path};

use librad::{git::storage, keys, meta, meta::entity, paths, peer::PeerId};
use radicle_surf::vcs::git::git2;

use crate::{config, error::Error, project, signer, state::State, user};

/// Deletes the local git repsoitory coco uses to keep its state.
///
/// # Errors
///
/// Will error in case the call to the [`std::fs::remove_dir_all`] fails.
pub fn nuke_monorepo() -> Result<(), std::io::Error> {
    let paths = paths::Paths::try_from(config::Paths::default()).expect("unable to create paths");
    std::fs::remove_dir_all(paths.git_dir())
}

/// Creates a small set of projects in your peer.
///
/// # Errors
///
/// Will error if filesystem access is not granted or broken for the configured
/// [`librad::paths::Paths`].
pub fn setup_fixtures(
    api: &State,
    signer: &signer::BoxedSigner,
    owner: &user::User,
) -> Result<(), Error> {
    let infos = vec![
        ("monokel", "A looking glass into the future", "master"),
        (
            "Monadic",
            "Open source organization of amazing things.",
            "master",
        ),
        (
            "open source coin",
            "Research for the sustainability of the open source community.",
            "master",
        ),
        (
            "radicle",
            "Decentralized open source collaboration",
            "master",
        ),
    ];

    for info in infos {
        replicate_platinum(api, signer, owner, info.0, info.1, info.2)?;
    }

    Ok(())
}

/// Create a copy of the git-platinum repo, init with coco and push tags and the additional dev
/// branch.
///
/// # Errors
///
/// Will return [`Error`] if any of the git interaction fail, or the initialisation of
/// the coco project.
pub fn replicate_platinum(
    api: &State,
    signer: &signer::BoxedSigner,
    owner: &user::User,
    name: &str,
    description: &str,
    default_branch: &str,
) -> Result<meta::project::Project<entity::Draft>, Error> {
    // Construct path for fixtures to clone into.
    let monorepo = api.monorepo();
    let workspace = monorepo.join("../workspace");
    let platinum_into = workspace.join(name);

    clone_platinum(&platinum_into)?;

    let project_creation = project::Create {
        description: description.to_string(),
        default_branch: default_branch.to_string(),
        repo: project::Repo::Existing {
            path: platinum_into.clone(),
        },
    };

    let meta = api.init_project(signer, owner, &project_creation)?;

    // Push branches and tags.
    {
        let repo = git2::Repository::open(platinum_into)?;
        let mut rad_remote = repo.find_remote("rad")?;

        // Push all tags to rad remote.
        let tags = repo
            .tag_names(None)?
            .into_iter()
            .flatten()
            .map(|t| format!("+refs/tags/{}", t))
            .collect::<Vec<_>>();
        rad_remote.push(&tags, None)?;

        // Push branches.
        rad_remote.push(&["refs/heads/dev", "refs/heads/master"], None)?;
    }

    // Init as rad project.
    Ok(meta)
}

/// Craft the absolute path to git-platinum fixtures.
///
/// # Errors
///
///   * Failed to get current directory
pub fn platinum_directory() -> io::Result<path::PathBuf> {
    let mut platinum_path = env::current_dir()?;

    if platinum_path.as_path().ends_with("proxy") {
        platinum_path.push("..");
    } else {
        platinum_path.push("../..");
    }

    platinum_path.push("fixtures/git-platinum");
    Ok(path::Path::new("file://").join(platinum_path))
}

/// Create and track a fake peer.
///
/// # Errors
///
/// * yo mamam
#[allow(clippy::panic)]
pub fn track_fake_peer(
    state: &State,
    signer: &signer::BoxedSigner,
    local_owner: &user::User,
    project: &meta::project::Project<entity::Draft>,
    handle: &str,
) -> Result<
    (
        PeerId,
        entity::Entity<meta::user::UserInfo, meta::entity::Verified>,
    ),
    Error,
> {
    // Create fresh storage
    let tmp_dir = tempfile::tempdir()?;
    let paths = paths::Paths::from_root(tmp_dir.path())?;
    let key = keys::SecretKey::new();
    let storage = storage::Storage::open_or_init(&paths, key.clone())?;

    // Create fake user/owner
    let owner = {
        let mut user = meta::user::User::<entity::Draft>::create(handle.to_string(), key.public())?;
        user.sign_owned(&key)?;
        let urn = user.urn();

        {
            if storage.has_urn(&urn)? {
                panic!("Entity exists");
            } else {
                storage.create_repo(&user)?;
            }
        }
        user::verify(user)?
    };

    // Clone local project
    {
        let mut meta = meta::project::Project::<entity::Draft>::create(
            project.name().to_string(),
            local_owner.urn(),
        )?
        .to_builder()
        .set_description(project.description().as_deref().unwrap_or("").to_string())
        .set_default_branch(project.default_branch().to_string())
        .add_key(key.public())
        .add_certifier(owner.urn())
        .build()?;

        meta.sign_owned(&key)?;

        let urn = meta.urn();

        let repo = storage.create_repo(&meta)?;
        // repo.set_rad_self(storage::RadSelfSpec::Urn(owner.urn()))?;
    };
    let remote_repo = git2::Repository::open(paths.git_dir())?;
    for reference in remote_repo.references()? {
        let reference = reference?;
        println!("REMOTE REF {:?}", reference.name());
    }

    // Fake fetching
    let mono_path = state.monorepo();
    let monorepo = git2::Repository::open(mono_path)?;
    let mut remote = monorepo.remote(
        &format!("local-remote-{}-{}", storage.peer_id(), handle),
        &format!("file://{}", paths.git_dir().display()),
    )?;

    println!("REMOTE file://{}", paths.git_dir().display());

    remote.connect(git2::Direction::Fetch)?;

    remote.fetch(
        &[&format!(
            "+refs/namespaces/{}/refs/rad/id:refs/namespaces/{}/remotes/{}/rad/id",
            project.urn().id,
            project.urn().id,
            storage.peer_id()
        )],
        None,
        None,
    )?;

    for remote in &monorepo.remotes()? {
        println!("REMOTE {:?}", remote);
    }
    for reference in monorepo.references()? {
        let reference = reference?;
        println!("REF {:?}", reference.name());
    }

    Ok((storage.peer_id().clone(), owner))
}

/// This function exists as a standalone because the logic does not play well with async in
/// `replicate_platinum`.
///
/// # Errors
///
///   * Cloning the repository failed
///   * We could not fetch branches
///
/// # Panics
///
///   * The platinum directory path was malformed
///   * Getting the branches fails
pub fn clone_platinum(platinum_into: impl AsRef<path::Path>) -> Result<(), Error> {
    let platinum_from = platinum_directory()?;
    let platinum_from = platinum_from
        .to_str()
        .expect("failed to get platinum directory");
    let mut fetch_options = git2::FetchOptions::new();
    fetch_options.download_tags(git2::AutotagOption::All);

    let platinum_repo = git2::build::RepoBuilder::new()
        .branch("master")
        .clone_local(git2::build::CloneLocal::Auto)
        .fetch_options(fetch_options)
        .clone(platinum_from, platinum_into.as_ref())?;

    {
        let branches = platinum_repo.branches(Some(git2::BranchType::Remote))?;

        for branch in branches {
            let (branch, _branch_type) = branch?;
            let name = &branch
                .name()
                .expect("unable to get branch name")
                .expect("branch not present")
                .get(7..)
                .expect("unable to extract branch name");
            let oid = branch.get().target().expect("can't find OID");
            let commit = platinum_repo.find_commit(oid)?;

            if *name != "master" {
                platinum_repo.branch(name, &commit, false)?;
            }
        }
    }

    Ok(())
}
