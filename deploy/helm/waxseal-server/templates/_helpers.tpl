{{/*
Name helpers. Standard Helm shapes; nothing waxseal-specific here.
*/}}
{{- define "waxseal-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "waxseal-server.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "waxseal-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "waxseal-server.labels" -}}
helm.sh/chart: {{ include "waxseal-server.chart" . }}
{{ include "waxseal-server.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: waxseal
waxseal.io/trust-domain: chain
{{- end -}}

{{/*
Image reference from an {repository, tag, digest} block. A digest, when set,
pins the bytes and wins; the tag still names the release for whoever reads the
manifest. Images are published cosign-signed BY DIGEST
(.github/workflows/publish-images.yml), and until 0.1.6 the chart offered no
way to pin to one while validate.yaml told operators to.
*/}}
{{- define "waxseal-server.image" -}}
{{- if .digest -}}
{{- printf "%s@%s" .repository .digest -}}
{{- else -}}
{{- printf "%s:%s" .repository .tag -}}
{{- end -}}
{{- end -}}

{{- define "waxseal-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "waxseal-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "waxseal-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "waxseal-server.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
The Secret the pod reads credentials from: the operator's own, or the one this
chart renders from inline values.
*/}}
{{- define "waxseal-server.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-credentials" (include "waxseal-server.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "waxseal-server.rendersOwnSecret" -}}
{{- if .Values.secrets.existingSecret -}}
{{- else if or .Values.secrets.apiKey .Values.secrets.witnessApiKey .Values.secrets.databaseUrl -}}
true
{{- end -}}
{{- end -}}

{{/*
Does this release have a PostgreSQL for operators and API keys? Either an
inline URL, or an existingSecret the operator DECLARED carries one. Never
inferred from an existingSecret's mere presence: Helm cannot read a Secret at
render time, and guessing here would either skip a seed that was needed or run
one that seeds a store thrown away when its pod exits.
*/}}
{{- define "waxseal-server.hasDatabase" -}}
{{- if .Values.secrets.databaseUrl -}}
true
{{- else if and .Values.secrets.existingSecret .Values.secrets.declaresDatabaseUrl -}}
true
{{- end -}}
{{- end -}}

{{/*
The credential environment. Every key is optional: an unset WAXSEAL_API_KEY
means the server is OPEN and says so at GET /v1/meta, and an unset database URL
means an in-memory operator store. Those are labelled states the server already
reports; a pod that refused to start would replace a labelled state with an
outage.
*/}}
{{- define "waxseal-server.credentialEnv" -}}
- name: WAXSEAL_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "waxseal-server.secretName" . }}
      key: WAXSEAL_API_KEY
      optional: true
- name: WAXSEAL_WITNESS_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "waxseal-server.secretName" . }}
      key: WAXSEAL_WITNESS_API_KEY
      optional: true
- name: WAXSEAL_SERVER_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "waxseal-server.secretName" . }}
      key: WAXSEAL_SERVER_DATABASE_URL
      optional: true
{{- end -}}
