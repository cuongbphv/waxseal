{{- define "waxseal-verifier.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "waxseal-verifier.fullname" -}}
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

{{- define "waxseal-verifier.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "waxseal-verifier.labels" -}}
helm.sh/chart: {{ include "waxseal-verifier.chart" . }}
{{ include "waxseal-verifier.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: waxseal
waxseal.io/trust-domain: verifier
{{- end -}}

{{- define "waxseal-verifier.selectorLabels" -}}
app.kubernetes.io/name: {{ include "waxseal-verifier.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "waxseal-verifier.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "waxseal-verifier.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "waxseal-verifier.secretName" -}}
{{- if .Values.credentials.existingSecret -}}
{{- .Values.credentials.existingSecret -}}
{{- else -}}
{{- printf "%s-credentials" (include "waxseal-verifier.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "waxseal-verifier.pinClaimName" -}}
{{- if .Values.verify.pin.existingClaim -}}
{{- .Values.verify.pin.existingClaim -}}
{{- else -}}
{{- printf "%s-pin" (include "waxseal-verifier.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "waxseal-verifier.pinPath" -}}
{{- printf "%s/%s" (.Values.verify.pin.mountPath | trimSuffix "/") .Values.verify.pin.fileName -}}
{{- end -}}

{{/*
The read credential. Optional on purpose: a public read point needs none
(server/docs/deployment.md, "Public read point"), and a pod that refused to
start without one would break the deployment shape the server was designed to
support.
*/}}
{{- define "waxseal-verifier.credentialEnv" -}}
- name: WAXSEAL_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "waxseal-verifier.secretName" . }}
      key: WAXSEAL_API_KEY
      optional: true
{{- end -}}
