# HAPass Invitations

🇬🇧 [English](#english) | 🇪🇸 [Español](#español)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## English

Fork of [Rohithkadaveru/ha-pass](https://github.com/Rohithkadaveru/ha-pass), an MIT-licensed
add-on for Home Assistant that creates shareable, time-limited guest links for controlling
specific entities. All credit for the original design (scoped tokens, the guest PWA, service
allowlisting, rate limiting, IP allowlisting) goes to the original author.

This fork adds **advance/recurring scheduling** and a few related features aimed at replacing
what a smart-intercom "guest invitation" feature typically offers (invite someone for a specific
future date/time, or a recurring weekly window), while staying self-hosted and auditable.

### What's new in this fork

- **Advance scheduling** — create a link today that only becomes active at a future date/time
  (`starts_at`), instead of always starting immediately.
- **Recurring weekly windows** — restrict a token to specific weekdays and a daily time range
  (e.g. every Tue/Thu 09:00–13:00), on top of the absolute expiry.
- **Automatic delivery** — optionally have HAPass send the guest link itself via any Home
  Assistant `notify.*` service, a configurable number of hours before it becomes active.
- **"First use" event** — a distinct `first_use` activity (alongside the existing `page_load`/
  `command` events) fires exactly once, the first time a link is actually opened — useful for a
  "your guest has arrived" notification.
- **`button` / `input_button` domain support** — these single-action, stateless entities (e.g. a
  helper wired to a gate/door relay via `shell_command`/`rest_command`) can now be exposed to
  guests; they weren't in the original service allowlist.
- **Narrow, opt-in entity suggestions** — a "Suggest entities" action in the admin UI scans your
  HA entities for two categories (*Access*: locks/covers/buttons matching door/gate keywords;
  *Lights*: the `light` domain) and pre-selects matches — you still review and adjust the
  selection. Three ready-made invitation modes (*Access only*/*Lights only*/*Access and lights*)
  just apply this filter. Deliberately narrow: it only ever suggests plausible candidates, it never
  auto-adds a whole dashboard's worth of entities.
- **Local-network-only command execution** — for access-type domains only (`lock`, `cover`,
  `button`, `input_button`), the guest link and its live state stay viewable from anywhere, but
  actually triggering the action is refused unless the request comes from a configured home-network
  CIDR range. **Honest limitation:** this checks the request's source IP, i.e. the guest's device
  has to actually be joined to that network at the moment they tap the button — it is not GPS-based
  proximity detection.
- **Single-device link binding** — the first browser/device to open a guest link claims it (a
  signed, `HttpOnly`/`SameSite=Strict` cookie scoped to that one link); any other device that opens
  the same link afterwards is refused, so a guest can't casually forward the link onward. An
  "Unbind" action in the admin UI releases the claim (e.g. the guest changed phones).

None of the above touches the original security model: the same entity/service allowlist,
forbidden-key stripping, rate limiting, and IP allowlisting from upstream still apply — these are
additive restrictions and scheduling features, not a rewrite of the trust boundary.

### Installation

#### Home Assistant Add-on

1. Add this repository in **Settings → Add-ons → Add-on Store → ⋮ → Repositories**:

   ```
   https://github.com/Nebur692/ha-pass-invitations
   ```

2. Find **HAPass** in the store and click **Install**.
3. Go to the **Configuration** tab and set your options (see below — a few are new in this fork).
4. Start the add-on.
5. Click **Open Web UI** or find HAPass in the HA sidebar.

Admin access works through the HA sidebar — no separate login needed. Guest links use the direct
port (`http://<your-ha-ip>:5880/g/{slug}`) so visitors don't need HA accounts.

#### Docker Compose

Pushing a `vX.Y.Z` tag to this repo triggers a GitHub Actions build that publishes to
`ghcr.io/nebur692/ha-pass-invitations`. Until a version has been tagged, build the image locally
from the `Dockerfile` instead of pulling a pre-built one.

```yaml
services:
  ha-pass:
    image: ghcr.io/nebur692/ha-pass-invitations:latest
    restart: unless-stopped
    ports:
      - 5880:5880
    volumes:
      - ./data:/data
    environment:
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=changeme
      - HA_BASE_URL=http://homeassistant.local:8123
      - HA_TOKEN=your_long_lived_token_here
      - TIMEZONE=Europe/Madrid
```

```bash
docker compose up -d
```

> **Note:** Docker deployments need a [long-lived access
> token](https://developers.home-assistant.io/docs/auth_api/#long-lived-access-token) from Home
> Assistant (**Profile → Security → Long-Lived Access Tokens**). The add-on handles this
> automatically.

### Configuration

In addition to every option from upstream (admin credentials, app name, contact message, branding,
log retention, guest URL — see [DOCS.md](DOCS.md)), this fork adds:

| Variable | Description | Default |
|---|---|---|
| `TIMEZONE` | IANA timezone used to evaluate recurring weekly windows | `UTC` |
| `LOCAL_NETWORK_CIDRS` | JSON array of CIDRs considered "home network" for access-domain commands (e.g. `["192.168.0.0/16"]`). Empty/unset = no restriction. | `[]` |

Per-token scheduling (`starts_at`, `recurrence`, `notify_service`, `notify_lead_seconds`) is set
from the admin dashboard's Create Token form — there's nothing to configure at the add-on level for
those.

### Supported Entity Types

Same as upstream, plus:

| Domain | Allowed Services |
|---|---|
| `button` | `press` |
| `input_button` | `press` |

`lock`, `cover`, `button`, and `input_button` are also the domains gated by
`LOCAL_NETWORK_CIDRS` when it's set.

### Disclaimer

Not affiliated with, endorsed by, or associated with Home Assistant or Nabu Casa Inc. "Home
Assistant" is a trademark of Nabu Casa Inc. Not affiliated with the original HAPass author beyond
this being an open, credited fork under the same MIT license.

### License

[MIT](LICENSE) — original copyright retained, fork changes are contributed under the same terms.

---

## Español

Fork de [Rohithkadaveru/ha-pass](https://github.com/Rohithkadaveru/ha-pass), un complemento con
licencia MIT para Home Assistant que crea enlaces de invitado, compartibles y con caducidad, para
controlar entidades concretas. Todo el crédito del diseño original (tokens acotados, la PWA de
invitado, lista blanca de servicios, rate limiting, lista blanca de IP) es del autor original.

Este fork añade **programación por adelantado/recurrente** y varias funciones relacionadas,
pensadas para sustituir lo que suele ofrecer la función de "invitación de invitados" de un
telefonillo inteligente (invitar a alguien para una fecha/hora futura concreta, o una ventana
semanal recurrente), manteniéndolo autoalojado y auditable.

### Novedades de este fork

- **Programación por adelantado** — crear hoy un enlace que solo se activa en una fecha/hora
  futura (`starts_at`), en vez de activarse siempre de inmediato.
- **Ventanas semanales recurrentes** — restringir un token a días concretos de la semana y una
  franja horaria diaria (p.ej. todos los martes/jueves 09:00–13:00), además de la caducidad
  absoluta.
- **Envío automático** — opcionalmente, que HAPass envíe el propio enlace por cualquier servicio
  `notify.*` de Home Assistant, con una antelación configurable en horas antes de que se active.
- **Evento de "primer uso"** — una actividad `first_use` distinta (junto a las ya existentes
  `page_load`/`command`) se dispara una única vez, la primera vez que el enlace se abre de
  verdad — útil para un aviso de "tu invitado ha llegado".
- **Soporte de dominio `button`/`input_button`** — estas entidades de acción única y sin estado
  (p.ej. un helper conectado a un relé de puerta/portón vía `shell_command`/`rest_command`) ya se
  pueden exponer a invitados; no estaban en la lista blanca de servicios original.
- **Sugerencias de entidades acotadas y opcionales** — una acción "Sugerir entidades" en el panel
  de administración escanea tus entidades de HA en dos categorías (*Accesos*: cerraduras/toldos/
  botones que coincidan con palabras clave de puerta/portón; *Luces*: dominio `light`) y
  preselecciona coincidencias — tú sigues revisando y ajustando la selección. Tres modos de
  invitación ya montados (*Solo accesos*/*Solo luces*/*Accesos y luces*) simplemente aplican ese
  filtro. Deliberadamente acotado: solo sugiere candidatos plausibles, nunca añade automáticamente
  todo un panel de entidades.
- **Ejecución de comandos restringida a la red local** — solo para dominios de tipo acceso
  (`lock`, `cover`, `button`, `input_button`), el enlace y su estado en vivo se siguen viendo desde
  cualquier sitio, pero la acción en sí se rechaza si la petición no viene de un rango CIDR
  configurado como "red de casa". **Limitación honesta:** esto comprueba la IP de origen de la
  petición, es decir, el dispositivo del invitado debe estar realmente unido a esa red en el
  momento de pulsar — no es detección de proximidad por GPS.
- **Vinculación del enlace a un solo dispositivo** — el primer navegador/dispositivo que abre un
  enlace de invitado lo reclama (una cookie firmada, `HttpOnly`/`SameSite=Strict`, acotada a ese
  enlace concreto); cualquier otro dispositivo que abra después el mismo enlace queda rechazado,
  así el invitado no puede reenviarlo sin más. Una acción "Desvincular" en el panel de
  administración libera la reclamación (p.ej. si el invitado cambia de móvil).

Nada de lo anterior toca el modelo de seguridad original: la misma lista blanca de entidad/
servicio, el filtrado de claves prohibidas, el rate limiting y la lista blanca de IP de la versión
original siguen aplicando — son restricciones y funciones de programación añadidas, no una
reescritura del límite de confianza.

### Instalación

#### Complemento de Home Assistant

1. Añade este repositorio en **Ajustes → Complementos → Tienda de complementos → ⋮ →
   Repositorios**:

   ```
   https://github.com/Nebur692/ha-pass-invitations
   ```

2. Busca **HAPass** en la tienda y pulsa **Instalar**.
3. Ve a la pestaña **Configuración** y ajusta tus opciones (ver abajo — algunas son nuevas de
   este fork).
4. Arranca el complemento.
5. Pulsa **Abrir interfaz web** o búscalo en la barra lateral de HA.

El acceso de administrador funciona a través de la barra lateral de HA — no hace falta iniciar
sesión aparte. Los enlaces de invitado usan el puerto directo
(`http://<tu-ip-de-ha>:5880/g/{slug}`) para que los visitantes no necesiten cuenta de HA.

#### Docker Compose

Al subir un tag `vX.Y.Z` a este repositorio se dispara una build de GitHub Actions que publica en
`ghcr.io/nebur692/ha-pass-invitations`. Hasta que exista una versión etiquetada, construye la
imagen en local desde el `Dockerfile` en vez de descargar una ya construida.

```yaml
services:
  ha-pass:
    image: ghcr.io/nebur692/ha-pass-invitations:latest
    restart: unless-stopped
    ports:
      - 5880:5880
    volumes:
      - ./data:/data
    environment:
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=changeme
      - HA_BASE_URL=http://homeassistant.local:8123
      - HA_TOKEN=your_long_lived_token_here
      - TIMEZONE=Europe/Madrid
```

```bash
docker compose up -d
```

> **Nota:** los despliegues Docker necesitan un [token de acceso de larga
> duración](https://developers.home-assistant.io/docs/auth_api/#long-lived-access-token) de Home
> Assistant (**Perfil → Seguridad → Tokens de acceso de larga duración**). El complemento lo
> gestiona automáticamente.

### Configuración

Además de todas las opciones ya existentes (credenciales de admin, nombre de la app, mensaje de
contacto, marca, retención de logs, URL de invitado — ver [DOCS.md](DOCS.md)), este fork añade:

| Variable | Descripción | Por defecto |
|---|---|---|
| `TIMEZONE` | Zona horaria IANA usada para evaluar las ventanas semanales recurrentes | `UTC` |
| `LOCAL_NETWORK_CIDRS` | Array JSON de CIDRs considerados "red de casa" para los comandos de dominios de acceso (p.ej. `["192.168.0.0/16"]`). Vacío/sin definir = sin restricción. | `[]` |

La programación por token (`starts_at`, `recurrence`, `notify_service`, `notify_lead_seconds`) se
configura desde el formulario de creación de token del panel de administración — no hay nada que
configurar a nivel de complemento para eso.

### Tipos de entidad soportados

Igual que la versión original, más:

| Dominio | Servicios permitidos |
|---|---|
| `button` | `press` |
| `input_button` | `press` |

`lock`, `cover`, `button` e `input_button` son también los dominios afectados por
`LOCAL_NETWORK_CIDRS` cuando está configurado.

### Aviso legal

No afiliado, respaldado ni asociado con Home Assistant ni Nabu Casa Inc. "Home Assistant" es una
marca registrada de Nabu Casa Inc. No afiliado con el autor original de HAPass más allá de ser un
fork abierto y con crédito bajo la misma licencia MIT.

### Licencia

[MIT](LICENSE) — se mantiene el copyright original; los cambios del fork se aportan bajo los
mismos términos.
