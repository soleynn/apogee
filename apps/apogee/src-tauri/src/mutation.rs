//! Path-free direct mutations over core-owned store and secret contracts.

use std::sync::{Arc, Mutex, MutexGuard};

use apogee_core::{Core, ListenerConsent, ProfileRemovalPlan, Secret, SecretKind, Uuid};

use crate::dto::IpcErrorDto;
use crate::dto::mutation::{
    DeleteSecretRequestDto, DisablePushedCodesRequestDto, ForgetSecretsRequestDto,
    ForgetSecretsResultDto, ImportTotpSecretRequestDto, NeverStoreResultDto, ProfileRemovalDto,
    ProfileRemovalPlanDto, RemoveProfileRequestDto, SetNeverStoreRequestDto,
    StorePasswordRequestDto, TotpImportResultDto, UpdateAccountRequestDto, UpdateProfileRequestDto,
    UpdateSettingsRequestDto, UsePushedCodesRequestDto,
};
use crate::dto::store::{AccountDto, ProfileDto, SettingsDto};
use crate::{ShellState, run_blocking};

struct PendingRemoval {
    request_id: Uuid,
    plan: ProfileRemovalPlan,
}

/// One opaque, process-local destructive decision. Opening a new confirmation invalidates the old
/// one, matching the shell's single dialog slot without handing the webview a forgeable plan.
#[derive(Default)]
pub(super) struct RemovalPlans {
    pending: Mutex<Option<PendingRemoval>>,
}

impl RemovalPlans {
    fn slot(&self) -> MutexGuard<'_, Option<PendingRemoval>> {
        match self.pending.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn replace(&self, plan: ProfileRemovalPlan) -> ProfileRemovalPlanDto {
        let request_id = Uuid::new_v4();
        let preview =
            ProfileRemovalPlanDto::new(request_id, plan.profile(), plan.account_removed());
        *self.slot() = Some(PendingRemoval { request_id, plan });
        preview
    }

    fn cancel(&self, request_id: Uuid) -> bool {
        let mut slot = self.slot();
        if slot
            .as_ref()
            .is_some_and(|pending| pending.request_id == request_id)
        {
            slot.take();
            true
        } else {
            false
        }
    }

    fn take(&self, request_id: Uuid) -> Option<ProfileRemovalPlan> {
        let mut slot = self.slot();
        if slot
            .as_ref()
            .is_some_and(|pending| pending.request_id == request_id)
        {
            slot.take().map(|pending| pending.plan)
        } else {
            None
        }
    }
}

async fn blocking_mutation<T, F>(state: &ShellState, task: F) -> Result<T, IpcErrorDto>
where
    T: Send + 'static,
    F: FnOnce(&Core) -> Result<T, IpcErrorDto> + Send + 'static,
{
    state.initial_snapshot().await?;
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    run_blocking(move || {
        let _lease = lease;
        task(&core)
    })
    .await?
}

#[tauri::command]
pub(super) async fn update_account(
    state: tauri::State<'_, ShellState>,
    request: UpdateAccountRequestDto,
) -> Result<AccountDto, IpcErrorDto> {
    let (account, square_enix_id, kind, use_otp) = request.into_parts();
    update_account_inner(&state, account, square_enix_id, kind, use_otp).await
}

async fn update_account_inner(
    state: &ShellState,
    account: Uuid,
    square_enix_id: String,
    kind: apogee_core::AccountKind,
    use_otp: bool,
) -> Result<AccountDto, IpcErrorDto> {
    blocking_mutation(state, move |core| {
        let mut record = core
            .account(account)
            .map_err(|error| IpcErrorDto::core(&error))?;
        record.sqex_id = square_enix_id;
        record.kind = kind;
        record.use_otp = use_otp;
        core.save_account(&record)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(AccountDto::from(&record))
    })
    .await
}

#[tauri::command]
pub(super) async fn update_profile(
    state: tauri::State<'_, ShellState>,
    request: UpdateProfileRequestDto,
) -> Result<ProfileDto, IpcErrorDto> {
    let (profile, name, runner, launch) = request.into_parts();
    update_profile_inner(&state, profile, name, runner, launch).await
}

async fn update_profile_inner(
    state: &ShellState,
    profile: Uuid,
    name: String,
    runner: apogee_core::RunnerSelection,
    launch: apogee_core::LaunchSettings,
) -> Result<ProfileDto, IpcErrorDto> {
    blocking_mutation(state, move |core| {
        let mut record = core
            .profile(profile)
            .map_err(|error| IpcErrorDto::core(&error))?;
        record.name = name;
        record.runner = runner;
        record.launch = launch;
        core.save_profile(&record)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(ProfileDto::from(&record))
    })
    .await
}

#[tauri::command]
pub(super) async fn update_settings(
    state: tauri::State<'_, ShellState>,
    request: UpdateSettingsRequestDto,
) -> Result<SettingsDto, IpcErrorDto> {
    update_settings_inner(&state, request.into_core()).await
}

async fn update_settings_inner(
    state: &ShellState,
    settings: apogee_core::Settings,
) -> Result<SettingsDto, IpcErrorDto> {
    blocking_mutation(state, move |core| {
        core.save_settings(&settings)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(SettingsDto::from(&settings))
    })
    .await
}

#[tauri::command]
pub(super) async fn store_password(
    state: tauri::State<'_, ShellState>,
    request: StorePasswordRequestDto,
) -> Result<(), IpcErrorDto> {
    // Move the IPC allocation into core's zeroizing type before the first scheduling point.
    let (account, password) = request.into_parts();
    store_secret_inner(&state, account, SecretKind::Password, password).await
}

async fn store_secret_inner(
    state: &ShellState,
    account: Uuid,
    kind: SecretKind,
    secret: Secret,
) -> Result<(), IpcErrorDto> {
    blocking_mutation(state, move |core| {
        core.store_secret(account, kind, secret)
            .map_err(|error| IpcErrorDto::core(&error))
    })
    .await
}

#[tauri::command]
pub(super) async fn import_totp_secret(
    state: tauri::State<'_, ShellState>,
    request: ImportTotpSecretRequestDto,
) -> Result<TotpImportResultDto, IpcErrorDto> {
    // Keep the pasted value zeroizing throughout parsing; UTF-8 validation borrows it in place.
    let (account, secret) = request.into_parts();
    import_totp_secret_inner(&state, account, secret).await
}

async fn import_totp_secret_inner(
    state: &ShellState,
    account: Uuid,
    secret: Secret,
) -> Result<TotpImportResultDto, IpcErrorDto> {
    blocking_mutation(state, move |core| {
        let offered = std::str::from_utf8(secret.expose())
            .map_err(|_| IpcErrorDto::shell("shell.command.invalid"))?;
        let deviations = core
            .import_totp_secret(account, offered)
            .map_err(|error| IpcErrorDto::core(&error))?;
        let account = core
            .account(account)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(TotpImportResultDto::new(
            AccountDto::from(&account),
            deviations,
        ))
    })
    .await
}

#[tauri::command]
pub(super) async fn use_pushed_codes(
    state: tauri::State<'_, ShellState>,
    request: UsePushedCodesRequestDto,
) -> Result<AccountDto, IpcErrorDto> {
    let (account, confirmation) = request.into_parts();
    use_pushed_codes_inner(&state, account, &confirmation).await
}

async fn use_pushed_codes_inner(
    state: &ShellState,
    account: Uuid,
    confirmation: &str,
) -> Result<AccountDto, IpcErrorDto> {
    if confirmation != "listen" {
        return Err(IpcErrorDto::shell("shell.confirmation.required"));
    }
    blocking_mutation(state, move |core| {
        core.use_pushed_codes(account, ListenerConsent::granted())
            .map_err(|error| IpcErrorDto::core(&error))?;
        core.account(account)
            .map(|account| AccountDto::from(&account))
            .map_err(|error| IpcErrorDto::core(&error))
    })
    .await
}

#[tauri::command]
pub(super) async fn forget_secrets(
    state: tauri::State<'_, ShellState>,
    request: ForgetSecretsRequestDto,
) -> Result<ForgetSecretsResultDto, IpcErrorDto> {
    let (account, confirmed) = request.into_parts();
    forget_secrets_inner(&state, account, confirmed).await
}

async fn forget_secrets_inner(
    state: &ShellState,
    account: Uuid,
    confirmed: bool,
) -> Result<ForgetSecretsResultDto, IpcErrorDto> {
    if !confirmed {
        return Err(IpcErrorDto::shell("shell.confirmation.required"));
    }
    blocking_mutation(state, move |core| {
        let sweep = core
            .forget_secrets(account)
            .map_err(|error| IpcErrorDto::core(&error))?;
        let account = core
            .account(account)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(ForgetSecretsResultDto::new(
            AccountDto::from(&account),
            sweep,
        ))
    })
    .await
}

#[tauri::command]
pub(super) async fn disable_pushed_codes(
    state: tauri::State<'_, ShellState>,
    request: DisablePushedCodesRequestDto,
) -> Result<AccountDto, IpcErrorDto> {
    disable_pushed_codes_inner(&state, request.account()).await
}

async fn disable_pushed_codes_inner(
    state: &ShellState,
    account: Uuid,
) -> Result<AccountDto, IpcErrorDto> {
    blocking_mutation(state, move |core| {
        core.ask_for_pushed_codes_no_longer(account)
            .map_err(|error| IpcErrorDto::core(&error))?;
        core.account(account)
            .map(|account| AccountDto::from(&account))
            .map_err(|error| IpcErrorDto::core(&error))
    })
    .await
}

#[tauri::command]
pub(super) async fn delete_secret(
    state: tauri::State<'_, ShellState>,
    request: DeleteSecretRequestDto,
) -> Result<AccountDto, IpcErrorDto> {
    let (account, kind, confirmed) = request.into_parts();
    delete_secret_inner(&state, account, kind, confirmed).await
}

async fn delete_secret_inner(
    state: &ShellState,
    account: Uuid,
    kind: SecretKind,
    confirmed: bool,
) -> Result<AccountDto, IpcErrorDto> {
    if !confirmed {
        return Err(IpcErrorDto::shell("shell.confirmation.required"));
    }
    blocking_mutation(state, move |core| {
        core.delete_secret(account, kind)
            .map_err(|error| IpcErrorDto::core(&error))?;
        core.account(account)
            .map(|account| AccountDto::from(&account))
            .map_err(|error| IpcErrorDto::core(&error))
    })
    .await
}

#[tauri::command]
pub(super) async fn set_never_store(
    state: tauri::State<'_, ShellState>,
    request: SetNeverStoreRequestDto,
) -> Result<NeverStoreResultDto, IpcErrorDto> {
    let (account, on) = request.into_parts();
    set_never_store_inner(&state, account, on).await
}

async fn set_never_store_inner(
    state: &ShellState,
    account: Uuid,
    on: bool,
) -> Result<NeverStoreResultDto, IpcErrorDto> {
    blocking_mutation(state, move |core| {
        let sweep = core
            .set_never_store(account, on)
            .map_err(|error| IpcErrorDto::core(&error))?;
        let account = core
            .account(account)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(NeverStoreResultDto::new(AccountDto::from(&account), sweep))
    })
    .await
}

#[tauri::command]
pub(super) async fn plan_profile_removal(
    state: tauri::State<'_, ShellState>,
    profile: String,
) -> Result<ProfileRemovalPlanDto, IpcErrorDto> {
    let profile =
        Uuid::parse_str(&profile).map_err(|_| IpcErrorDto::shell("shell.command.invalid"))?;
    state.initial_snapshot().await?;
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    let removal_plans = Arc::clone(&state.removal_plans);
    run_blocking(move || {
        let _lease = lease;
        let plan = core
            .plan_removal(profile)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(removal_plans.replace(plan))
    })
    .await?
}

#[tauri::command]
pub(super) async fn cancel_profile_removal(
    state: tauri::State<'_, ShellState>,
    request_id: String,
) -> Result<bool, IpcErrorDto> {
    let Ok(request_id) = Uuid::parse_str(&request_id) else {
        return Ok(false);
    };
    Ok(state.removal_plans.cancel(request_id))
}

#[tauri::command]
pub(super) async fn remove_profile(
    state: tauri::State<'_, ShellState>,
    request: RemoveProfileRequestDto,
) -> Result<ProfileRemovalDto, IpcErrorDto> {
    let (request_id, confirmed) = request.into_parts();
    remove_profile_inner(&state, &request_id, confirmed).await
}

async fn remove_profile_inner(
    state: &ShellState,
    request_id: &str,
    confirmed: bool,
) -> Result<ProfileRemovalDto, IpcErrorDto> {
    if !confirmed {
        return Err(IpcErrorDto::shell("shell.confirmation.required"));
    }
    let request_id =
        Uuid::parse_str(request_id).map_err(|_| IpcErrorDto::shell("shell.command.invalid"))?;
    state.initial_snapshot().await?;
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    let plan = state
        .removal_plans
        .take(request_id)
        .ok_or_else(|| IpcErrorDto::shell("shell.removal-plan.unavailable"))?;
    let profile = plan.profile();
    let result = run_blocking(move || {
        let _lease = lease;
        core.remove_profile(plan)
            .map(|removal| ProfileRemovalDto::new(profile, removal))
            .map_err(|error| IpcErrorDto::core(&error))
    })
    .await;
    result?
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use apogee_core::{
        Account, AccountKind, Consent, CoreConfig, OtpDelivery, Passphrase, PrefixSelection,
        Profile, RunnerSelection, SecretBackend, SecretsError,
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn ipc_error(error: IpcErrorDto) -> Box<dyn std::error::Error> {
        std::io::Error::other(
            serde_json::to_string(&error).unwrap_or_else(|_| "IPC failure".to_owned()),
        )
        .into()
    }

    struct FixedPassphrase;

    impl Passphrase for FixedPassphrase {
        fn unlock(&self) -> Result<Secret, SecretsError> {
            Ok(Secret::new(b"test passphrase".to_vec()))
        }
    }

    fn secret_state() -> TestResult<(tempfile::TempDir, ShellState, Account)> {
        let temporary = tempfile::TempDir::new()?;
        let config = CoreConfig::with_base(temporary.path());
        let bootstrap = Core::new(config.clone())?;
        let mut settings = bootstrap.settings()?;
        settings.secret_backend = SecretBackend::EncryptedFile;
        bootstrap.save_settings(&settings)?;
        drop(bootstrap);
        let core = Core::with_passphrase(config, Arc::new(FixedPassphrase))?;
        core.create_secrets_file(
            Consent::granted(),
            &Secret::new(b"test passphrase".to_vec()),
        )?;
        let account = Account::new("person@example.invalid", AccountKind::Standard);
        core.save_account(&account)?;
        let state = ShellState::default();
        state.install_core(Ok(core));
        Ok((temporary, state, account))
    }

    async fn seeded_state() -> TestResult<(tempfile::TempDir, ShellState, Account, Profile)> {
        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        let mut account = Account::new("before@example.invalid", AccountKind::Standard);
        account.never_store = true;
        account.otp_delivery = OtpDelivery::Listen;
        core.save_account(&account)?;
        let mut profile = Profile::new("Before", account.id, PathBuf::from("protected/game/path"));
        profile.prefix = PrefixSelection {
            name: "protected-prefix".to_owned(),
        };
        core.save_profile(&profile)?;
        let state = ShellState::default();
        state.install_core(Ok(core));
        Ok((temporary, state, account, profile))
    }

    #[tokio::test]
    async fn account_update_preserves_secret_policy_fields() -> TestResult {
        let (_temporary, state, account, _profile) = seeded_state().await?;
        update_account_inner(
            &state,
            account.id,
            "after@example.invalid".to_owned(),
            AccountKind::FreeTrial,
            false,
        )
        .await
        .map_err(ipc_error)?;

        let saved = state
            .ready_core()
            .await
            .map_err(ipc_error)?
            .account(account.id)?;
        assert_eq!(saved.sqex_id, "after@example.invalid");
        assert_eq!(saved.kind, AccountKind::FreeTrial);
        assert!(!saved.use_otp);
        assert!(saved.never_store);
        assert_eq!(saved.otp_delivery, OtpDelivery::Listen);
        Ok(())
    }

    #[tokio::test]
    async fn profile_update_preserves_ownership_and_paths() -> TestResult {
        let (_temporary, state, account, profile) = seeded_state().await?;
        let mut launch = profile.launch.clone();
        launch.extra_args = vec!["--changed".to_owned()];
        update_profile_inner(
            &state,
            profile.id,
            "After".to_owned(),
            RunnerSelection::Managed {
                name: "runner".to_owned(),
                version: "1".to_owned(),
            },
            launch.clone(),
        )
        .await
        .map_err(ipc_error)?;

        let saved = state
            .ready_core()
            .await
            .map_err(ipc_error)?
            .profile(profile.id)?;
        assert_eq!(saved.name, "After");
        assert_eq!(saved.account, account.id);
        assert_eq!(saved.game_path, PathBuf::from("protected/game/path"));
        assert_eq!(saved.prefix.name, "protected-prefix");
        assert_eq!(saved.launch, launch);
        Ok(())
    }

    #[tokio::test]
    async fn removal_requires_the_exact_live_opaque_plan() -> TestResult {
        let (_temporary, state, _account, profile) = seeded_state().await?;
        let core = state.ready_core().await.map_err(ipc_error)?;
        core.save_profile(&Profile::new("Shared", profile.account, "shared".into()))?;
        let preview = state.removal_plans.replace(core.plan_removal(profile.id)?);
        let wrong = Uuid::new_v4().to_string();
        let missing = remove_profile_inner(&state, &wrong, true).await;
        assert!(missing.is_err());

        let request_id = preview.request_id().to_owned();
        remove_profile_inner(&state, &request_id, true)
            .await
            .map_err(ipc_error)?;
        assert!(core.profile(profile.id).is_err());
        let replay = remove_profile_inner(&state, &request_id, true).await;
        assert!(replay.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn busy_admission_does_not_consume_a_removal_plan() -> TestResult {
        let (_temporary, state, _account, profile) = seeded_state().await?;
        let core = state.ready_core().await.map_err(ipc_error)?;
        core.save_profile(&Profile::new("Shared", profile.account, "shared".into()))?;
        let preview = state.removal_plans.replace(core.plan_removal(profile.id)?);
        let request_id = preview.request_id().to_owned();
        let occupied = state.mutation_lease().map_err(ipc_error)?;

        let busy = remove_profile_inner(&state, &request_id, true).await;
        assert!(busy.is_err());
        drop(occupied);
        remove_profile_inner(&state, &request_id, true)
            .await
            .map_err(ipc_error)?;
        assert!(core.profile(profile.id).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn secret_mutations_return_metadata_without_echoing_inputs() -> TestResult {
        let (_temporary, state, account) = secret_state()?;
        let password = b"planted-password";
        store_secret_inner(
            &state,
            account.id,
            SecretKind::Password,
            Secret::new(password.to_vec()),
        )
        .await
        .map_err(ipc_error)?;

        let offered = b"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let imported = import_totp_secret_inner(&state, account.id, Secret::new(offered.to_vec()))
            .await
            .map_err(ipc_error)?;
        let json = serde_json::to_string(&imported)?;
        assert!(json.contains(r#""otpDelivery":"generate""#));
        assert!(!json.contains("JBSWY3D"));
        assert!(!json.contains("planted-password"));

        let deleted = delete_secret_inner(&state, account.id, SecretKind::TotpSecret, true)
            .await
            .map_err(ipc_error)?;
        assert!(serde_json::to_string(&deleted)?.contains(r#""otpDelivery":"ask""#));
        let listening = use_pushed_codes_inner(&state, account.id, "listen")
            .await
            .map_err(ipc_error)?;
        assert!(serde_json::to_string(&listening)?.contains(r#""otpDelivery":"listen""#));
        let typed = disable_pushed_codes_inner(&state, account.id)
            .await
            .map_err(ipc_error)?;
        assert!(serde_json::to_string(&typed)?.contains(r#""otpDelivery":"ask""#));

        let forgotten = forget_secrets_inner(&state, account.id, true)
            .await
            .map_err(ipc_error)?;
        assert!(serde_json::to_string(&forgotten)?.contains(r#""secretSweep":"swept""#));
        store_secret_inner(
            &state,
            account.id,
            SecretKind::Password,
            Secret::new(password.to_vec()),
        )
        .await
        .map_err(ipc_error)?;
        let policy = set_never_store_inner(&state, account.id, true)
            .await
            .map_err(ipc_error)?;
        let json = serde_json::to_string(&policy)?;
        assert!(json.contains(r#""neverStore":true"#));
        assert!(json.contains(r#""secretSweep":"swept""#));
        assert!(!json.contains("planted-password"));
        Ok(())
    }

    #[tokio::test]
    async fn unconfirmed_mutations_do_not_wait_for_core() {
        let state = ShellState::default();
        assert!(
            use_pushed_codes_inner(&state, Uuid::nil(), "LISTEN")
                .await
                .is_err()
        );
        assert!(
            delete_secret_inner(&state, Uuid::nil(), SecretKind::Password, false)
                .await
                .is_err()
        );
        assert!(
            forget_secrets_inner(&state, Uuid::nil(), false)
                .await
                .is_err()
        );
        assert!(
            remove_profile_inner(&state, &Uuid::nil().to_string(), false)
                .await
                .is_err()
        );
    }

    #[test]
    fn replacing_and_cancelling_plans_invalidates_old_capabilities() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let core = Core::new(CoreConfig::with_base(temporary.path()))?;
        let account = Account::new("person@example.invalid", AccountKind::Standard);
        core.save_account(&account)?;
        let first = Profile::new("First", account.id, "first".into());
        let second = Profile::new("Second", account.id, "second".into());
        core.save_profile(&first)?;
        core.save_profile(&second)?;
        let plans = RemovalPlans::default();
        let first = plans.replace(core.plan_removal(first.id)?);
        let second = plans.replace(core.plan_removal(second.id)?);
        let first_id = Uuid::parse_str(first.request_id())?;
        let second_id = Uuid::parse_str(second.request_id())?;

        assert!(plans.take(first_id).is_none());
        assert!(plans.cancel(second_id));
        assert!(!plans.cancel(second_id));
        Ok(())
    }
}
