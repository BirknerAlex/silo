{{- define "silo.fullname" -}}
{{- .Release.Name }}-silo
{{- end -}}

{{- define "silo.postgres.fullname" -}}
{{ include "silo.fullname" . }}-postgres
{{- end -}}

{{/*
The label set that identifies a pod to its Service, ServiceMonitor and
Deployment.

Kept separate from `silo.labels` and deliberately *not* extensible: a
Deployment's `spec.selector` is immutable, so if user-supplied labels ended
up here, adding one would make every subsequent `helm upgrade` fail with an
error that gives no hint about the cause. These two keys are exactly what
previous chart versions selected on, so upgrades keep working.
*/}}
{{- define "silo.selectorLabels" -}}
app.kubernetes.io/name: silo
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Labels for the `metadata` of every silo resource: the selector keys, the
standard Kubernetes recommended set, and whatever `commonLabels` adds.

Safe to extend because metadata labels are mutable, which is the whole
reason this is a different template from the one above.
*/}}
{{- define "silo.labels" -}}
{{ include "silo.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: silo
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "silo.postgres.selectorLabels" -}}
app.kubernetes.io/name: silo-postgres
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "silo.postgres.labels" -}}
{{ include "silo.postgres.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: silo
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Annotations applied to every resource the chart creates.

Emits the whole block — its own newline, the `annotations:` key, and two
spaces of indent — so that a resource with none at all produces nothing
rather than a stray blank line or a dangling empty map. That fixed indent
is why it is called bare, with no `nindent`; every call site sits directly
under a `metadata:`.

  {{- include "silo.annotations" (dict "ctx" . "extra" .Values.service.annotations) }}
*/}}
{{- define "silo.annotations" -}}
{{- $merged := merge (dict) (default (dict) .extra) (default (dict) .ctx.Values.commonAnnotations) -}}
{{- if $merged }}
  annotations:
    {{- toYaml $merged | nindent 4 }}
{{- end }}
{{- end -}}

{{- define "silo.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ .Values.serviceAccount.name | default (include "silo.fullname" .) }}
{{- else -}}
{{ .Values.serviceAccount.name | default "default" }}
{{- end -}}
{{- end -}}

{{- define "silo.configSecretName" -}}
{{- if .Values.existingConfigSecret -}}
{{ .Values.existingConfigSecret }}
{{- else -}}
{{ include "silo.fullname" . }}-config
{{- end -}}
{{- end -}}

{{/*
The database URL, injected as an environment variable rather than baked
into config.yaml so that an external Postgres password can come from an
existing Secret without the chart ever templating it into a file.
Exactly one of postgres.enabled / externalPostgres must be configured.
*/}}
{{- define "silo.databaseUrlEnv" -}}
{{- if and .Values.postgres.enabled (or .Values.externalPostgres.url .Values.externalPostgres.existingSecret) -}}
{{- fail "set either postgres.enabled or externalPostgres, not both" -}}
{{- end -}}
{{- if .Values.postgres.enabled -}}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.existingSecret | default (printf "%s-postgres" (include "silo.fullname" .)) }}
      key: password
- name: SILO_DATABASE_URL
  value: "postgres://{{ .Values.postgres.username }}:$(POSTGRES_PASSWORD)@{{ include "silo.postgres.fullname" . }}:5432/{{ .Values.postgres.database }}"
{{- else if .Values.externalPostgres.existingSecret -}}
- name: SILO_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.externalPostgres.existingSecret }}
      key: {{ .Values.externalPostgres.existingSecretKey }}
{{- else if .Values.externalPostgres.url -}}
- name: SILO_DATABASE_URL
  value: {{ .Values.externalPostgres.url | quote }}
{{- else if not .Values.existingConfigSecret -}}
{{- fail "a database is required: set postgres.enabled=true for a bundled dev instance, or externalPostgres.url / externalPostgres.existingSecret" -}}
{{- end -}}
{{- end -}}

{{/*
Renders config.yaml from the structured values. `configOverride` bypasses
this entirely for setups that would rather hand-write the file.
*/}}
{{- define "silo.config" -}}
{{- if .Values.configOverride -}}
{{ .Values.configOverride }}
{{- else -}}
grpc_addr: "0.0.0.0:{{ .Values.service.grpcPort }}"
http_addr: "0.0.0.0:{{ .Values.service.httpPort }}"
{{- with .Values.config.publicBaseUrl }}
public_base_url: {{ . | quote }}
{{- end }}

database:
  # Expanded from the environment by silo's config loader, so the password
  # can come from a Secret without ever being templated into this file or
  # into Helm release history.
  url: "${SILO_DATABASE_URL}"

storage:
  bucket: {{ .Values.config.storage.bucket | quote }}
  region: {{ .Values.config.storage.region | quote }}
  {{- with .Values.config.storage.endpoint }}
  endpoint: {{ . | quote }}
  {{- end }}
  allow_http: {{ .Values.config.storage.allowHttp }}
  {{- if .Values.config.storage.existingSecret }}
  access_key_id: "${SILO_STORAGE_ACCESS_KEY_ID}"
  secret_access_key: "${SILO_STORAGE_SECRET_ACCESS_KEY}"
  {{- else }}
  access_key_id: {{ .Values.config.storage.accessKeyId | quote }}
  secret_access_key: {{ .Values.config.storage.secretAccessKey | quote }}
  {{- end }}

auth:
  bootstrap: {{ .Values.config.auth.bootstrap }}
  session_ttl_hours: {{ .Values.config.auth.sessionTtlHours }}
  allow_anonymous_read: {{ .Values.config.auth.allowAnonymousRead }}
  {{- if .Values.config.auth.tokenPepperExistingSecret }}
  token_pepper: "${SILO_TOKEN_PEPPER}"
  {{- else if .Values.config.auth.tokenPepper }}
  token_pepper: {{ .Values.config.auth.tokenPepper | quote }}
  {{- end }}

audit:
  log_downloads: {{ .Values.config.audit.logDownloads }}
  retention_days: {{ .Values.config.audit.retentionDays }}

metrics:
  enabled: {{ .Values.config.metrics.enabled }}
  require_auth: {{ .Values.config.metrics.requireAuth }}

{{- if .Values.config.oidc.issuer }}

oidc:
  issuer: {{ .Values.config.oidc.issuer | quote }}
  client_id: {{ .Values.config.oidc.clientId | quote }}
  username_claim: {{ .Values.config.oidc.usernameClaim | quote }}
  scopes:
    {{- range .Values.config.oidc.scopes }}
    - {{ . | quote }}
    {{- end }}
  {{- with .Values.config.oidc.adminClaim }}
  admin_claim: {{ . | quote }}
  {{- end }}
  {{- with .Values.config.oidc.adminValue }}
  admin_value: {{ . | quote }}
  {{- end }}
  exclusive: {{ .Values.config.oidc.exclusive }}
{{- end }}

{{- if or .Values.config.signing.gpg.key .Values.config.signing.gpg.existingSecret .Values.config.signing.apk.key .Values.config.signing.apk.existingSecret }}

signing:
  {{- if .Values.config.signing.gpg.existingSecret }}
  gpg:
    key_path: /etc/silo/signing/gpg-key.asc
    {{- with .Values.config.signing.gpg.passphrase }}
    passphrase: {{ . | quote }}
    {{- end }}
  {{- else if .Values.config.signing.gpg.key }}
  gpg:
    key: |
{{ .Values.config.signing.gpg.key | indent 6 }}
    {{- with .Values.config.signing.gpg.passphrase }}
    passphrase: {{ . | quote }}
    {{- end }}
  {{- end }}
  {{- if .Values.config.signing.apk.existingSecret }}
  apk:
    key_path: /etc/silo/signing/apk-key.pem
    key_name: {{ .Values.config.signing.apk.keyName | quote }}
  {{- else if .Values.config.signing.apk.key }}
  apk:
    key: |
{{ .Values.config.signing.apk.key | indent 6 }}
    key_name: {{ .Values.config.signing.apk.keyName | quote }}
  {{- end }}
{{- end }}
{{- end -}}
{{- end -}}
