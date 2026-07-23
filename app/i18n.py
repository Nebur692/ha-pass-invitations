"""Minimal i18n: Accept-Language detection + EN/ES string tables.

Two independent audiences, two detection strategies:
  - Guest PWA: always auto-detected from the guest's own browser
    (Accept-Language). No override — a guest link isn't "owned" by anyone
    who'd have a profile to configure.
  - Admin dashboard: auto-detected by default, but overridable via a
    persisted cookie set from the admin's own Profile section (see
    app/routers/admin.py `/admin/profile/language`).

No third language, no pluralization engine, no .po files — just two flat
dicts per audience. If a third language is ever needed, revisit then.
"""
from fastapi import Request

SUPPORTED_LANGS = ("en", "es")
DEFAULT_LANG = "en"

ADMIN_LANG_COOKIE = "hp_admin_lang"


def _parse_accept_language(header: str) -> list[str]:
    tags: list[tuple[str, float]] = []
    for part in header.split(","):
        part = part.strip()
        if not part:
            continue
        if ";q=" in part:
            tag, q = part.split(";q=", 1)
            try:
                weight = float(q)
            except ValueError:
                weight = 1.0
        else:
            tag, weight = part, 1.0
        tags.append((tag.strip().lower(), weight))
    tags.sort(key=lambda x: x[1], reverse=True)
    return [t for t, _ in tags]


def detect_lang(accept_language: str | None) -> str:
    if not accept_language:
        return DEFAULT_LANG
    for tag in _parse_accept_language(accept_language):
        primary = tag.split("-")[0]
        if primary in SUPPORTED_LANGS:
            return primary
    return DEFAULT_LANG


def get_guest_lang(request: Request) -> str:
    return detect_lang(request.headers.get("accept-language"))


def get_admin_lang(request: Request) -> str:
    cookie_val = request.cookies.get(ADMIN_LANG_COOKIE)
    if cookie_val in SUPPORTED_LANGS:
        return cookie_val
    return detect_lang(request.headers.get("accept-language"))


def is_admin_lang_auto(request: Request) -> bool:
    return request.cookies.get(ADMIN_LANG_COOKIE) not in SUPPORTED_LANGS


def make_t(strings: dict[str, dict[str, str]], lang: str):
    """Returns a t(key, **kwargs) callable bound to the resolved language.

    Falls back to English for any key missing in a non-English table, then
    to the raw key itself if truly missing everywhere (so a typo shows up
    as an ugly-but-visible key rather than a blank string).
    """
    table = strings.get(lang, strings[DEFAULT_LANG])
    fallback = strings[DEFAULT_LANG]

    def t(key: str, **kwargs) -> str:
        text = table.get(key, fallback.get(key, key))
        for k, v in kwargs.items():
            text = text.replace("{" + k + "}", str(v))
        return text

    return t


# ---------------------------------------------------------------------------
# Admin dashboard strings
# ---------------------------------------------------------------------------

ADMIN_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "admin_access": "Admin Access",
        "username": "Username",
        "password": "Password",
        "sign_in": "Sign in",
        "sign_out": "Sign out",
        "profile": "Profile",
        "invalid_credentials": "Invalid credentials.",
        "connection_error": "Connection error.",
        "guest_tokens_heading": "Guest Tokens",
        "create_token": "Create Token",
        "stat_active": "Active",
        "stat_expired": "Expired",
        "recent_activity": "Recent Activity",
        "show_all": "Show all",
        "show_less": "Show less",
        "refresh_activity": "Refresh activity",
        "loading": "Loading...",
        "no_activity_yet": "No activity yet",
        "activity_used": "{label} used {service}",
        "activity_opened_link": "{label} opened link",
        "deleted_token": "Deleted token",
        "guest_page": "Guest page",
        "no_tokens_yet_title": "No tokens yet",
        "no_tokens_yet_body": "Create a token to give guests temporary access.",
        "badge_active": "Active",
        "badge_expiring": "Expiring",
        "badge_expired": "Expired",
        "badge_revoked": "Revoked",
        "action_renew": "Renew",
        "action_extend": "Extend",
        "duplicate": "Duplicate",
        "delete": "Delete",
        "entities_count": "{n} entities",
        "expires_label": "Expires {t}",
        "never": "Never",
        "any_ip": "Any IP",
        "starts_label": "Starts {t}",
        "linked_since": "Linked to a device since {t}",
        "not_claimed": "Not yet claimed by a device",
        "copy": "Copy",
        "qr": "QR",
        "edit": "Edit",
        "revoke": "Revoke",
        "unbind_device": "Unbind device",
        "single_use_badge": "Single use",
        "uses_left": "{used}/{max} uses",

        "create_modal_title": "Create Guest Token",
        "duplicate_modal_title": "Duplicate Guest Token",
        "label_field": "Label",
        "label_placeholder": "e.g. Airbnb Guest - John",
        "custom_slug": "Custom Slug",
        "optional": "(optional)",
        "slug_placeholder": "Leave blank for random",
        "slug_hint": "Custom slugs are guessable. Use random slugs for external access.",
        "expiry": "Expiry",
        "opt_1_hour": "1 hour",
        "opt_12_hours": "12 hours",
        "opt_1_day": "1 day",
        "opt_3_days": "3 days",
        "opt_7_days": "7 days",
        "opt_30_days": "30 days",
        "opt_90_days": "90 days",
        "opt_1_year": "1 year",
        "opt_never_expires": "Never expires",
        "opt_custom": "Custom...",
        "never_expires_warn": "This token grants permanent access until manually revoked.",
        "custom_date_future_error": "Date must be in the future.",
        "single_use_hint": "The link stops working after the first action a guest takes (opening a door, pressing a button...).",
        "ip_allowlist": "IP Allowlist",
        "invitation_mode": "Invitation Mode",
        "opt_manual_selection": "Manual selection",
        "opt_access_only": "Access only",
        "opt_lights_only": "Lights only",
        "opt_access_and_lights": "Access and lights",
        "mode_hint": "Pre-selects entities below by keyword/domain (locks, doors, gates / lights). You can still edit the selection freely.",
        "entities": "Entities",
        "schedule_section_title": "Timing",
        "mode_single_use": "Single use",
        "mode_never_expires": "No expiry",
        "mode_period": "Set a period",
        "period_hint": "Active only between the dates below.",
        "period_starts_at": "Starts",
        "period_ends_at": "Ends",
        "err_period_dates_required": "Choose a start and end date/time.",
        "err_period_end_after_start": "End must be after start.",
        "err_period_end_in_past": "End must be in the future.",
        "advanced_period_toggle": "Repeat weekly / auto-send link (advanced)",
        "repeat_weekly": "Repeat weekly (only allow access within this window on the selected days)",
        "weekday_mon": "Mon", "weekday_tue": "Tue", "weekday_wed": "Wed", "weekday_thu": "Thu",
        "weekday_fri": "Fri", "weekday_sat": "Sat", "weekday_sun": "Sun",
        "notify_via": "Send link automatically via",
        "send_hours_before": "Send this many hours before it starts",
        "cancel": "Cancel",
        "create": "Create",
        "save": "Save",
        "close_dialog": "Close dialog",

        "err_label_required": "Label is required.",
        "err_invalid_expiry": "Invalid expiry date. Must be in the future.",
        "err_select_entity": "Select at least one entity.",
        "err_choose_datetime": "Choose a start date/time.",
        "err_select_weekday": "Select at least one day for the recurring schedule.",
        "err_end_after_start": "Recurring end time must be after start time.",
        "err_creating_token": "Error creating token.",
        "err_updating_entities": "Error updating entities.",
        "err_updating_expiry": "Error updating expiry.",

        "toast_token_created": "Token created",
        "toast_url_copied": "URL copied",
        "toast_entities_updated": "Entities updated",
        "toast_expiry_updated": "Expiry updated",
        "toast_token_revoked": "Token revoked",
        "toast_error_revoking": "Error revoking token",
        "toast_token_deleted": "Token deleted",
        "toast_error_deleting": "Error deleting token",
        "toast_device_unbound": "Device unbound",
        "toast_error_unbinding": "Error unbinding token",
        "toast_failed_load_suggestions": "Failed to load suggestions",
        "toast_failed_load_token": "Failed to load token",
        "toast_language_updated": "Language updated",

        "edit_modal_title": "Edit Entities",
        "editing_prefix": "Editing: {label}",
        "loading_entities": "Loading entities...",

        "extend_title": "Extend Expiry",
        "renew_title": "Renew Expiry",
        "extend_prefix": "Extend: {label}",
        "renew_prefix": "Renew: {label}",
        "new_expiry_label": "New Expiry (From Now)",
        "extend_hint": "Replaces the current expiry with a new one from now.",

        "confirm_revoke_title": "Revoke Token",
        "confirm_revoke_body": "Active guest sessions will be disconnected immediately.",
        "confirm_delete_title": "Delete Token",
        "confirm_delete_body": "This will permanently remove the token record.",
        "confirm_unbind_title": "Unbind Device",
        "confirm_unbind_body": "The next device that opens this link will claim it. Use this if the guest lost or changed their phone.",
        "confirm": "Confirm",

        "qr_code_title": "QR Code",
        "copy_link": "Copy Link",

        "search_entities_placeholder": "Search entities...",
        "selected_count": "Selected ({n})",
        "available_count": "Available ({n})",
        "and_more": "...and {n} more. Use search to filter.",
        "no_matching_entities": "No matching entities",
        "selected_footer": "{n} selected",
        "filter_all": "All",
        "filter_media": "Media",
        "remove_aria": "Remove {name}",
        "add_aria": "Add {name}",

        "profile_modal_title": "Profile",
        "language_label": "Language",
        "lang_auto": "Auto (browser language)",
        "lang_en": "English",
        "lang_es": "Español",
    },
    "es": {
        "admin_access": "Acceso de administrador",
        "username": "Usuario",
        "password": "Contraseña",
        "sign_in": "Iniciar sesión",
        "sign_out": "Cerrar sesión",
        "profile": "Perfil",
        "invalid_credentials": "Credenciales inválidas.",
        "connection_error": "Error de conexión.",
        "guest_tokens_heading": "Tokens de invitado",
        "create_token": "Crear token",
        "stat_active": "Activos",
        "stat_expired": "Caducados",
        "recent_activity": "Actividad reciente",
        "show_all": "Ver todo",
        "show_less": "Ver menos",
        "refresh_activity": "Actualizar actividad",
        "loading": "Cargando...",
        "no_activity_yet": "Sin actividad todavía",
        "activity_used": "{label} usó {service}",
        "activity_opened_link": "{label} abrió el enlace",
        "deleted_token": "Token eliminado",
        "guest_page": "Página de invitado",
        "no_tokens_yet_title": "Aún no hay tokens",
        "no_tokens_yet_body": "Crea un token para dar acceso temporal a tus invitados.",
        "badge_active": "Activo",
        "badge_expiring": "Por caducar",
        "badge_expired": "Caducado",
        "badge_revoked": "Revocado",
        "action_renew": "Renovar",
        "action_extend": "Extender",
        "duplicate": "Duplicar",
        "delete": "Eliminar",
        "entities_count": "{n} entidades",
        "expires_label": "Caduca {t}",
        "never": "Nunca",
        "any_ip": "Cualquier IP",
        "starts_label": "Empieza {t}",
        "linked_since": "Vinculado a un dispositivo desde {t}",
        "not_claimed": "Aún no reclamado por ningún dispositivo",
        "copy": "Copiar",
        "qr": "QR",
        "edit": "Editar",
        "revoke": "Revocar",
        "unbind_device": "Desvincular dispositivo",
        "single_use_badge": "Un solo uso",
        "uses_left": "{used}/{max} usos",

        "create_modal_title": "Crear token de invitado",
        "duplicate_modal_title": "Duplicar token de invitado",
        "label_field": "Etiqueta",
        "label_placeholder": "p.ej. Invitado Airbnb - Juan",
        "custom_slug": "Slug personalizado",
        "optional": "(opcional)",
        "slug_placeholder": "Déjalo en blanco para uno aleatorio",
        "slug_hint": "Los slugs personalizados se pueden adivinar. Usa uno aleatorio para acceso externo.",
        "expiry": "Caducidad",
        "opt_1_hour": "1 hora",
        "opt_12_hours": "12 horas",
        "opt_1_day": "1 día",
        "opt_3_days": "3 días",
        "opt_7_days": "7 días",
        "opt_30_days": "30 días",
        "opt_90_days": "90 días",
        "opt_1_year": "1 año",
        "opt_never_expires": "No caduca nunca",
        "opt_custom": "Personalizado...",
        "never_expires_warn": "Este token da acceso permanente hasta que lo revoques a mano.",
        "custom_date_future_error": "La fecha debe ser futura.",
        "single_use_hint": "El enlace deja de funcionar después de la primera acción del invitado (abrir una puerta, pulsar un botón...).",
        "ip_allowlist": "Lista blanca de IP",
        "invitation_mode": "Modo de invitación",
        "opt_manual_selection": "Selección manual",
        "opt_access_only": "Solo accesos",
        "opt_lights_only": "Solo luces",
        "opt_access_and_lights": "Accesos y luces",
        "mode_hint": "Preselecciona entidades abajo por palabra clave/dominio (cerraduras, puertas, portones / luces). Puedes editar la selección libremente.",
        "entities": "Entidades",
        "schedule_section_title": "Horario",
        "mode_single_use": "Un solo uso",
        "mode_never_expires": "Sin caducidad",
        "mode_period": "Periodo",
        "period_hint": "Activo solo entre las fechas de abajo.",
        "period_starts_at": "Empieza",
        "period_ends_at": "Termina",
        "err_period_dates_required": "Elige fecha/hora de inicio y de fin.",
        "err_period_end_after_start": "El fin debe ser posterior al inicio.",
        "err_period_end_in_past": "El fin debe ser futuro.",
        "advanced_period_toggle": "Repetir semanalmente / enviar automáticamente (avanzado)",
        "repeat_weekly": "Repetir cada semana (solo permite acceso en esta franja los días seleccionados)",
        "weekday_mon": "Lun", "weekday_tue": "Mar", "weekday_wed": "Mié", "weekday_thu": "Jue",
        "weekday_fri": "Vie", "weekday_sat": "Sáb", "weekday_sun": "Dom",
        "notify_via": "Enviar el enlace automáticamente vía",
        "send_hours_before": "Enviarlo con estas horas de antelación",
        "cancel": "Cancelar",
        "create": "Crear",
        "save": "Guardar",
        "close_dialog": "Cerrar diálogo",

        "err_label_required": "La etiqueta es obligatoria.",
        "err_invalid_expiry": "Fecha de caducidad inválida. Debe ser futura.",
        "err_select_entity": "Selecciona al menos una entidad.",
        "err_choose_datetime": "Elige fecha/hora de inicio.",
        "err_select_weekday": "Selecciona al menos un día para el horario recurrente.",
        "err_end_after_start": "La hora de fin debe ser posterior a la de inicio.",
        "err_creating_token": "Error al crear el token.",
        "err_updating_entities": "Error al actualizar entidades.",
        "err_updating_expiry": "Error al actualizar la caducidad.",

        "toast_token_created": "Token creado",
        "toast_url_copied": "URL copiada",
        "toast_entities_updated": "Entidades actualizadas",
        "toast_expiry_updated": "Caducidad actualizada",
        "toast_token_revoked": "Token revocado",
        "toast_error_revoking": "Error al revocar el token",
        "toast_token_deleted": "Token eliminado",
        "toast_error_deleting": "Error al eliminar el token",
        "toast_device_unbound": "Dispositivo desvinculado",
        "toast_error_unbinding": "Error al desvincular el token",
        "toast_failed_load_suggestions": "No se pudieron cargar las sugerencias",
        "toast_failed_load_token": "No se pudo cargar el token",
        "toast_language_updated": "Idioma actualizado",

        "edit_modal_title": "Editar entidades",
        "editing_prefix": "Editando: {label}",
        "loading_entities": "Cargando entidades...",

        "extend_title": "Extender caducidad",
        "renew_title": "Renovar caducidad",
        "extend_prefix": "Extender: {label}",
        "renew_prefix": "Renovar: {label}",
        "new_expiry_label": "Nueva caducidad (desde ahora)",
        "extend_hint": "Sustituye la caducidad actual por una nueva desde ahora.",

        "confirm_revoke_title": "Revocar token",
        "confirm_revoke_body": "Las sesiones de invitado activas se desconectarán al instante.",
        "confirm_delete_title": "Eliminar token",
        "confirm_delete_body": "Esto eliminará el registro del token de forma permanente.",
        "confirm_unbind_title": "Desvincular dispositivo",
        "confirm_unbind_body": "El próximo dispositivo que abra este enlace lo reclamará. Útil si el invitado perdió o cambió de móvil.",
        "confirm": "Confirmar",

        "qr_code_title": "Código QR",
        "copy_link": "Copiar enlace",

        "search_entities_placeholder": "Buscar entidades...",
        "selected_count": "Seleccionadas ({n})",
        "available_count": "Disponibles ({n})",
        "and_more": "...y {n} más. Usa la búsqueda para filtrar.",
        "no_matching_entities": "No hay entidades que coincidan",
        "selected_footer": "{n} seleccionadas",
        "filter_all": "Todo",
        "filter_media": "Multimedia",
        "remove_aria": "Quitar {name}",
        "add_aria": "Añadir {name}",

        "profile_modal_title": "Perfil",
        "language_label": "Idioma",
        "lang_auto": "Automático (idioma del navegador)",
        "lang_en": "English",
        "lang_es": "Español",
    },
}


# ---------------------------------------------------------------------------
# Guest PWA strings
# ---------------------------------------------------------------------------

GUEST_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "js_required": "JavaScript is required to use this app.",
        "connecting": "Connecting",
        "live": "Live",
        "offline": "Offline",
        "remaining": "Remaining",
        "expired_word": "Expired",
        "no_expiration": "No expiration",
        "install_title": "Install as App",
        "install_ios_html": 'Tap <span class="inline-flex items-center align-middle mx-0.5"><span class="material-symbols-outlined text-sm text-accent">ios_share</span></span> then <strong>"Add to Home Screen"</strong> for the best experience.',
        "install_android_html": 'Tap <span class="inline-flex items-center align-middle mx-0.5"><span class="material-symbols-outlined text-sm text-accent">more_vert</span></span> then <strong>"Install app"</strong> or <strong>"Add to Home Screen"</strong>.',
        "loading_devices": "Loading devices...",
        "no_devices": "No devices assigned to this session.",
        "failed_load_devices": "Failed to load devices.",
        "sheet_confirm_default": "Confirm",
        "cancel": "Cancel",
        "confirm": "Confirm",
        "unlock_door_q": "Unlock door?",
        "lock_door_q": "Lock door?",
        "will_unlock": "This will unlock the door.",
        "will_lock": "This will lock the door.",
        "open_latch_q": "Open latch?",
        "will_open_latch": "This will open the latch.",
        "press": "Press",
        "open": "Open",
        "stop": "Stop",
        "close": "Close",
        "tap_to_unlock": "Tap to Unlock",
        "tap_to_lock": "Tap to Lock",
        "playing": "Playing",
        "paused": "Paused",
        "idle": "Idle",
        "locked": "Locked",
        "unlocked": "Unlocked",
        "on_word": "On",
        "off_word": "Off",
        "ready": "Ready",
        "unavailable": "Unavailable",
        "target_label": "Target: {t}{u}",
        "humidity_suffix": " · {h}% humidity",
        "too_many_requests": "Too many requests — slow down",
        "need_home_wifi": "You need to be connected to the home Wi-Fi for this",
        "command_failed": "Command failed",
        "appear_offline": "You appear to be offline",

        "title_expired": "Access Expired",
        "body_expired": "This guest session has ended or the link is no longer valid.",
        "title_revoked": "Access Revoked",
        "body_revoked": "This link has been revoked by the host.",
        "title_used_up": "Link Already Used",
        "body_used_up": "This link was for a single use and has already been used.",
        "session_ended_short": "Your guest session has ended.",

        "not_active_title": "Not Active Yet",
        "not_active_body_prefix": "This link isn't active yet",
        "not_active_check_back": " — check back ",

        "aria_volume": "Volume",
        "aria_brightness": "Brightness",
        "aria_fan_speed": "Fan speed",
        "aria_decrease_temp": "Decrease temperature",
        "aria_increase_temp": "Increase temperature",
        "aria_hvac_mode": "HVAC mode",
        "aria_toggle": "Toggle {name}",
    },
    "es": {
        "js_required": "Se necesita JavaScript para usar esta app.",
        "connecting": "Conectando",
        "live": "En directo",
        "offline": "Sin conexión",
        "remaining": "Restante",
        "expired_word": "Caducado",
        "no_expiration": "Sin caducidad",
        "install_title": "Instalar como app",
        "install_ios_html": 'Toca <span class="inline-flex items-center align-middle mx-0.5"><span class="material-symbols-outlined text-sm text-accent">ios_share</span></span> y luego <strong>"Añadir a pantalla de inicio"</strong> para la mejor experiencia.',
        "install_android_html": 'Toca <span class="inline-flex items-center align-middle mx-0.5"><span class="material-symbols-outlined text-sm text-accent">more_vert</span></span> y luego <strong>"Instalar app"</strong> o <strong>"Añadir a pantalla de inicio"</strong>.',
        "loading_devices": "Cargando dispositivos...",
        "no_devices": "No hay dispositivos asignados a esta sesión.",
        "failed_load_devices": "No se pudieron cargar los dispositivos.",
        "sheet_confirm_default": "Confirmar",
        "cancel": "Cancelar",
        "confirm": "Confirmar",
        "unlock_door_q": "¿Desbloquear la puerta?",
        "lock_door_q": "¿Bloquear la puerta?",
        "will_unlock": "Esto desbloqueará la puerta.",
        "will_lock": "Esto bloqueará la puerta.",
        "open_latch_q": "¿Abrir el pestillo?",
        "will_open_latch": "Esto abrirá el pestillo.",
        "press": "Pulsar",
        "open": "Abrir",
        "stop": "Detener",
        "close": "Cerrar",
        "tap_to_unlock": "Toca para desbloquear",
        "tap_to_lock": "Toca para bloquear",
        "playing": "Reproduciendo",
        "paused": "Pausado",
        "idle": "Inactivo",
        "locked": "Bloqueada",
        "unlocked": "Desbloqueada",
        "on_word": "Encendido",
        "off_word": "Apagado",
        "ready": "Listo",
        "unavailable": "No disponible",
        "target_label": "Objetivo: {t}{u}",
        "humidity_suffix": " · {h}% de humedad",
        "too_many_requests": "Demasiadas peticiones — más despacio",
        "need_home_wifi": "Necesitas estar conectado al Wi-Fi de casa para esto",
        "command_failed": "Falló el comando",
        "appear_offline": "Parece que estás sin conexión",

        "title_expired": "Acceso caducado",
        "body_expired": "Esta sesión de invitado ha terminado o el enlace ya no es válido.",
        "title_revoked": "Acceso revocado",
        "body_revoked": "El anfitrión ha revocado este enlace.",
        "title_used_up": "Enlace ya utilizado",
        "body_used_up": "Este enlace era de un solo uso y ya se ha utilizado.",
        "session_ended_short": "Tu sesión de invitado ha terminado.",

        "not_active_title": "Todavía no está activo",
        "not_active_body_prefix": "Este enlace todavía no está activo",
        "not_active_check_back": " — vuelve a comprobarlo el ",

        "aria_volume": "Volumen",
        "aria_brightness": "Brillo",
        "aria_fan_speed": "Velocidad del ventilador",
        "aria_decrease_temp": "Bajar temperatura",
        "aria_increase_temp": "Subir temperatura",
        "aria_hvac_mode": "Modo de climatización",
        "aria_toggle": "Alternar {name}",
    },
}
