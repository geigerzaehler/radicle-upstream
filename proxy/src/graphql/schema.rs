use std::convert::From;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync;

use librad::paths::Paths;
use librad::surf;
use librad::surf::git::git2;
use radicle_registry_client::ed25519;

use crate::coco;
use crate::error;
use crate::identity;
use crate::project;
use crate::registry;

/// Glue to bundle our read and write APIs together.
pub type Schema = juniper::RootNode<'static, Query, Mutation>;

/// Returns a `Schema` with the default parameterised `Query` and `Mutation`.
#[must_use]
pub fn create() -> Schema {
    Schema::new(Query {}, Mutation {})
}

/// Container for data access from handlers.
#[derive(Clone)]
pub struct Context {
    /// Root on the filesystem for the librad config and storage paths.
    librad_paths: sync::Arc<sync::RwLock<Paths>>,
    /// Wrapper to interact with the Registry.
    registry: sync::Arc<sync::RwLock<registry::Registry>>,
}

impl Context {
    /// Returns a new `Context`.
    #[must_use]
    pub fn new(librad_paths: Paths, registry_client: radicle_registry_client::Client) -> Self {
        Self {
            librad_paths: sync::Arc::new(sync::RwLock::new(librad_paths)),
            registry: sync::Arc::new(sync::RwLock::new(registry::Registry::new(registry_client))),
        }
    }
}

impl juniper::Context for Context {}

/// Encapsulates write path in API.
pub struct Mutation;

#[juniper::object(
    Context = Context,
    name = "UpstreamMutation",
)]
impl Mutation {
    fn create_identity(
        _ctx: &Context,
        handle: String,
        display_name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<identity::Identity, error::Error> {
        Ok(identity::Identity {
            id: "123abcd.git".into(),
            shareable_entity_identifier: format!("{}@123abcd.git", handle),
            metadata: identity::Metadata {
                handle,
                display_name,
                avatar_url,
            },
        })
    }

    fn create_project(
        ctx: &Context,
        metadata: ProjectMetadataInput,
        path: String,
        publish: bool,
    ) -> Result<project::Project, error::Error> {
        if surf::git::git2::Repository::open(path.clone()).is_err() {
            coco::init_repo(path.clone())?;
        };

        let (id, meta) = coco::init_project(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
            &path,
            &metadata.name,
            &metadata.description,
            &metadata.default_branch,
            &metadata.img_url,
        )?;

        Ok(project::Project {
            id: librad::project::ProjectId::from(id),
            metadata: meta.into(),
        })
    }

    fn register_project(
        ctx: &Context,
        project_name: String,
        org_id: String,
        maybe_librad_id_input: Option<juniper::ID>,
    ) -> Result<registry::Transaction, error::Error> {
        let maybe_librad_id = maybe_librad_id_input.map(|id| {
            librad::project::ProjectId::from_str(&id.to_string())
                .expect("unable to parse project id")
        });

        // TODO(xla): Get keypair from persistent storage.
        let fake_pair = ed25519::Pair::from_legacy_string("//Robot", None);
        // TODO(xla): Remove single-threaded executor once async/await lands in juniper:
        // https://github.com/graphql-rust/juniper/pull/497
        futures::executor::block_on(
            ctx.registry
                .read()
                .expect("unable to acquire read lock")
                .register_project(&fake_pair, project_name, org_id, maybe_librad_id),
        )
    }

    fn register_user(
        ctx: &Context,
        handle: juniper::ID,
        id: juniper::ID,
    ) -> Result<registry::Transaction, error::Error> {
        // TODO(xla): Get keypair from persistent storage.
        let fake_pair = ed25519::Pair::from_legacy_string("//Robot", None);

        futures::executor::block_on(
            ctx.registry
                .read()
                .expect("unable to acquire read lock")
                .register_user(&fake_pair, handle.to_string(), id.to_string()),
        )
    }
}

/// Encapsulates read paths in API.
pub struct Query;

#[juniper::object(
    Context = Context,
    name = "UpstreamQuery",
)]
impl Query {
    fn apiVersion() -> &str {
        "1.0"
    }

    fn blob(
        ctx: &Context,
        id: juniper::ID,
        revision: String,
        path: String,
    ) -> Result<coco::Blob, error::Error> {
        coco::blob(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
            &id.to_string(),
            &revision,
            &path,
        )
    }

    fn commit(ctx: &Context, id: juniper::ID, sha1: String) -> Result<coco::Commit, error::Error> {
        coco::commit(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
            &id.to_string(),
            &sha1,
        )
    }

    fn branches(ctx: &Context, id: juniper::ID) -> Result<Vec<String>, error::Error> {
        Ok(coco::branches(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
            &id.to_string(),
        )?
        .into_iter()
        .map(|t| t.to_string())
        .collect())
    }

    fn local_branches(ctx: &Context, path: String) -> Result<Vec<String>, error::Error> {
        Ok(coco::local_branches(&path)?
            .into_iter()
            .map(|t| t.to_string())
            .collect())
    }

    fn tags(ctx: &Context, id: juniper::ID) -> Result<Vec<String>, error::Error> {
        Ok(coco::tags(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
            &id.to_string(),
        )?
        .into_iter()
        .map(|t| t.to_string())
        .collect())
    }

    fn tree(
        ctx: &Context,
        id: juniper::ID,
        revision: String,
        prefix: String,
    ) -> Result<coco::Tree, error::Error> {
        coco::tree(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
            &id,
            &revision,
            &prefix,
        )
    }

    fn project(ctx: &Context, id: juniper::ID) -> Result<project::Project, error::Error> {
        let meta = coco::get_project_meta(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
            &id.to_string(),
        )?;

        Ok(project::Project {
            id: librad::project::ProjectId::from_str(&id.to_string())?,
            metadata: meta.into(),
        })
    }

    fn projects(ctx: &Context) -> Result<Vec<project::Project>, error::Error> {
        let projects = coco::list_projects(
            &ctx.librad_paths
                .read()
                .expect("unable to acquire read lock"),
        )
        .into_iter()
        .map(|(id, meta)| project::Project {
            id,
            metadata: meta.into(),
        })
        .collect::<Vec<project::Project>>();

        Ok(projects)
    }

    fn list_registry_projects(ctx: &Context) -> Result<Vec<juniper::ID>, error::Error> {
        let ids = futures::executor::block_on(
            ctx.registry
                .read()
                .expect("unable to acquire read lock")
                .list_projects(),
        )?;

        Ok(ids
            .iter()
            .map(|id| juniper::ID::from(id.0.to_string()))
            .collect::<Vec<juniper::ID>>())
    }

    fn identity(
        _ctx: &Context,
        id: juniper::ID,
    ) -> Result<Option<identity::Identity>, error::Error> {
        Ok(Some(identity::Identity {
            id: id.to_string(),
            shareable_entity_identifier: format!("cloudhead@{}", id.to_string()),
            metadata: identity::Metadata {
                handle: "cloudhead".into(),
                display_name: Some("Alexis Sellier".into()),
                avatar_url: Some("https://avatars1.githubusercontent.com/u/4077".into()),
            },
        }))
    }

    fn user(_ctx: &Context, handle: juniper::ID) -> Result<Option<juniper::ID>, error::Error> {
        Ok(None)
    }
}

/// Bundles `Query` and `Mutation` used for controlling raw state.
pub type Control = juniper::RootNode<'static, ControlQuery, ControlMutation>;

/// Returns the [`Control`] schema used for controlling raw state.
#[must_use]
pub fn create_control() -> Control {
    Control::new(ControlQuery {}, ControlMutation {})
}

/// Control mutations.
pub struct ControlMutation;

#[juniper::object(
    Context = Context,
    name = "ControlMutation",
    description = "Mutations to control raw proxy state.",
)]
impl ControlMutation {
    fn create_project_with_fixture(
        ctx: &Context,
        metadata: ProjectMetadataInput,
    ) -> Result<project::Project, error::Error> {
        let tmp_dir = tempfile::tempdir()?;
        let paths = &ctx
            .librad_paths
            .read()
            .expect("unable to acquire lock for librad paths");
        let (id, meta) = coco::replicate_platinum(
            &tmp_dir,
            paths,
            &metadata.name,
            &metadata.description,
            &metadata.default_branch,
            &metadata.img_url,
        )?;

        Ok(project::Project {
            id: id.into(),
            metadata: meta.into(),
        })
    }

    fn nuke_coco_state(ctx: &Context) -> Result<bool, error::Error> {
        let tmp_dir = tempfile::tempdir().expect("creating temporary directory for paths failed");
        let new_paths = Paths::from_root(tmp_dir.path()).expect("unable to get librad paths");

        let mut librad_paths = ctx.librad_paths.write().expect("unable to get write lock");

        *librad_paths = new_paths;

        Ok(true)
    }

    fn nuke_registry_state(ctx: &Context) -> Result<bool, error::Error> {
        ctx.registry
            .write()
            .expect("unable to get write lock")
            .reset(radicle_registry_client::Client::new_emulator());

        Ok(true)
    }
}

/// Control query endpoints.
pub struct ControlQuery;

#[juniper::object(
    Context = Context,
    name = "ControlQuery",
    description = "Queries to access raw proxy state.",
)]
impl ControlQuery {}

#[juniper::object]
impl coco::Blob {
    fn binary(&self) -> bool {
        match &self.content {
            coco::BlobContent::Ascii(_content) => false,
            coco::BlobContent::Binary => true,
        }
    }

    fn content(&self) -> Option<String> {
        match &self.content {
            coco::BlobContent::Ascii(content) => Some(content.clone()),
            coco::BlobContent::Binary => None,
        }
    }

    fn info(&self) -> &coco::Info {
        &self.info
    }
}

#[juniper::object]
impl coco::Commit {
    fn sha1(&self) -> String {
        self.sha1.to_string()
    }

    fn author(&self) -> &coco::Person {
        &self.author
    }

    fn summary(&self) -> &str {
        &self.summary
    }

    fn message(&self) -> &str {
        &self.message
    }

    fn committer_time(&self) -> String {
        self.committer_time.seconds().to_string()
    }
}

#[juniper::object]
impl coco::Info {
    fn name(&self) -> &str {
        &self.name
    }

    fn object_type(&self) -> ObjectType {
        match self.object_type {
            coco::ObjectType::Blob => ObjectType::Blob,
            coco::ObjectType::Tree => ObjectType::Tree,
        }
    }

    fn last_commit(&self) -> Option<&coco::Commit> {
        self.last_commit.as_ref()
    }
}

/// Git object types.
///
/// <https://git-scm.com/book/en/v2/Git-Internals-Git-Objects>
#[derive(GraphQLEnum)]
enum ObjectType {
    /// Directory tree.
    Tree,
    /// Text or binary blob of a file.
    Blob,
}

#[juniper::object]
impl coco::Person {
    fn name(&self) -> &str {
        &self.name
    }

    fn email(&self) -> &str {
        &self.email
    }

    fn avatar(&self) -> &str {
        &self.avatar
    }
}

#[juniper::object]
impl coco::Tree {
    fn path(&self) -> &str {
        &self.path
    }

    fn entries(&self) -> &Vec<coco::TreeEntry> {
        self.entries.as_ref()
    }

    fn info(&self) -> &coco::Info {
        &self.info
    }
}

#[juniper::object]
impl coco::TreeEntry {
    fn info(&self) -> &coco::Info {
        &self.info
    }

    fn path(&self) -> String {
        self.path.clone()
    }
}

#[juniper::object]
impl identity::Identity {
    fn id(&self) -> juniper::ID {
        juniper::ID::new(&self.id)
    }

    fn shareable_entity_identifier(&self) -> juniper::ID {
        juniper::ID::new(&self.shareable_entity_identifier)
    }

    fn metadata(&self) -> &identity::Metadata {
        &self.metadata
    }
}

#[juniper::object(name = "IdentityMetadata")]
impl identity::Metadata {
    fn avatar_url(&self) -> Option<&String> {
        self.avatar_url.as_ref()
    }

    fn display_name(&self) -> Option<&String> {
        self.display_name.as_ref()
    }

    fn handle(&self) -> &str {
        &self.handle
    }
}

/// Input object capturing the fields we need to create project metadata.
#[derive(GraphQLInputObject)]
#[graphql(description = "Input object for project metadata")]
pub struct ProjectMetadataInput {
    /// Project name.
    pub name: String,
    /// High-level description of the project.
    pub description: String,
    /// Default branch for checkouts, often used as mainline as well.
    pub default_branch: String,
    /// Image url for the project.
    pub img_url: String,
}

#[juniper::object]
impl project::Project {
    fn id(&self) -> juniper::ID {
        juniper::ID::new(&self.id.to_string())
    }

    fn metadata(&self) -> &project::Metadata {
        &self.metadata
    }
    fn registered(&self) -> bool {
        false
    }

    fn stats(&self) -> &project::Stats {
        &project::Stats {
            branches: 11,
            commits: 267,
            contributors: 8,
        }
    }
}

#[juniper::object(name = "ProjectMetadata")]
impl project::Metadata {
    fn default_branch(&self) -> &str {
        &self.default_branch
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn img_url(&self) -> &str {
        &self.img_url
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[juniper::object(name = "ProjectStats")]
impl project::Stats {
    fn branches(&self) -> i32 {
        i32::try_from(self.branches).expect("unable to convert branches number")
    }

    fn commits(&self) -> i32 {
        i32::try_from(self.commits).expect("unable to convert branches number")
    }

    fn contributors(&self) -> i32 {
        i32::try_from(self.contributors).expect("unable to convert branches number")
    }
}

/// Shows if a project exists on the Registry and distinguishes between Org and User owned.
#[derive(GraphQLEnum)]
pub enum ProjectRegistered {
    /// Project is not present on the Registry.
    Not,
}

#[juniper::object]
impl registry::Transaction {
    fn id(&self) -> juniper::ID {
        juniper::ID::new(self.id.to_string())
    }

    fn messages(&self) -> Vec<Message> {
        self.messages
            .iter()
            .map(|m| match m {
                registry::Message::OrgRegistration(org_id) => {
                    Message::OrgRegistration(OrgRegistration {
                        org_id: juniper::ID::new(org_id.to_string()),
                    })
                },
                registry::Message::OrgUnregistration(org_id) => {
                    Message::OrgUnregistration(OrgUnregistration {
                        org_id: juniper::ID::new(org_id.to_string()),
                    })
                },
                registry::Message::ProjectRegistration {
                    project_name,
                    org_id,
                } => Message::ProjectRegistration(ProjectRegistration {
                    project_name: juniper::ID::new(project_name.to_string()),
                    org_id: juniper::ID::new(org_id.to_string()),
                }),
                registry::Message::UserRegistration { handle, id } => {
                    Message::UserRegistration(UserRegistration {
                        handle: juniper::ID::new(handle.to_string()),
                        id: juniper::ID::new(id.to_string()),
                    })
                },
            })
            .collect()
    }

    fn state(&self) -> TransactionState {
        match self.state {
            registry::TransactionState::Applied(block_hash) => TransactionState::Applied(Applied {
                block: juniper::ID::new(block_hash.to_string()),
            }),
        }
    }

    fn timestamp(&self) -> juniper::FieldResult<String> {
        let since_epoch = i64::try_from(
            self.timestamp
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?;
        let git_time = git2::Time::new(since_epoch, 0).seconds().to_string();

        Ok(git_time)
    }
}

/// Message types supproted in transactions.
enum Message {
    /// Registration of a new org.
    OrgRegistration(OrgRegistration),

    /// Registration of a new org.
    OrgUnregistration(OrgUnregistration),

    /// Registration of a new project.
    ProjectRegistration(ProjectRegistration),

    /// Registration of a new user.
    UserRegistration(UserRegistration),
}

juniper::graphql_union!(Message: () where Scalar = <S> |&self| {
    instance_resolvers: |_| {
        &OrgRegistration => match *self {
            Message::OrgRegistration(ref o) => Some(o),
            Message::OrgUnregistration(..) | Message::ProjectRegistration(..) | Message::UserRegistration(..) => None,
        },
        &OrgUnregistration => match *self {
            Message::OrgUnregistration(ref o) => Some(o),
            Message::OrgRegistration(..) | Message::ProjectRegistration(..) | Message::UserRegistration(..) => None,
        },
        &ProjectRegistration => match *self {
            Message::ProjectRegistration(ref p) => Some(p),
            Message::OrgRegistration(..) | Message::OrgUnregistration(..) | Message::UserRegistration(..) => None,
        },
        &UserRegistration => match *self {
            Message::UserRegistration(ref o) => Some(o),
            Message::OrgRegistration(..) | Message::OrgUnregistration(..) | Message::ProjectRegistration(..) => None,
        }
    }
});

/// Contextual information for an org registration message.
#[derive(juniper::GraphQLObject)]
struct OrgRegistration {
    /// The ID of the org.
    org_id: juniper::ID,
}

/// Contextual information for an org unregistration message.
#[derive(juniper::GraphQLObject)]
struct OrgUnregistration {
    /// The ID of the org.
    org_id: juniper::ID,
}

/// Contextual information for a project registration message.
#[derive(juniper::GraphQLObject)]
struct ProjectRegistration {
    /// Actual project name, unique under org.
    project_name: juniper::ID,
    /// The org under which to register the project.
    org_id: juniper::ID,
}

/// Payload of a user registration message.
#[derive(juniper::GraphQLObject)]
struct UserRegistration {
    /// The chosen unique handle to be registered.
    handle: juniper::ID,
    /// The id of the librad identity.
    id: juniper::ID,
}

/// States a transaction can go through.
enum TransactionState {
    /// The transaction has been applied to a block.
    Applied(Applied),
}

/// Context for a chain applied transaction.
#[derive(GraphQLObject)]
struct Applied {
    /// Block hash the transaction was included in.
    block: juniper::ID,
}

juniper::graphql_union!(TransactionState: () where Scalar = <S> |&self| {
    instance_resolvers: |_| {
        &Applied => match *self { TransactionState::Applied(ref a) => Some(a) },
    }
});