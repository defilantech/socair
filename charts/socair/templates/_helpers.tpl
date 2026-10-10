{{- define "socair.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "socair.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "socair.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "socair.selectorLabels" -}}
app.kubernetes.io/name: {{ include "socair.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "socair.labels" -}}
helm.sh/chart: {{ include "socair.chart" . }}
{{ include "socair.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "socair.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "socair.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* The image, pinned by digest when one is given. */}}
{{- define "socair.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
The address the API binds. Loopback unless a Service exposes it: the API has
no authentication, and the engine refuses a public bind without
SOCAIR_API_ALLOW_PUBLIC=1 (docs/api.md).
*/}}
{{- define "socair.apiAddr" -}}
{{- if .Values.service.enabled }}0.0.0.0:8080{{ else }}127.0.0.1:8080{{ end }}
{{- end }}

{{- define "socair.storeClaim" -}}
{{- default (printf "%s-store" (include "socair.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}

{{/* Settings that would deploy something unsafe or broken fail the install. */}}
{{- define "socair.validate" -}}
{{- if and .Values.service.enabled (not .Values.service.authenticatingProxy) }}
{{- fail "service.enabled exposes the Socair API, which has no authentication of its own. Put an authenticating proxy in front of it and set service.authenticatingProxy=true to confirm, or reach the wizard with kubectl port-forward (the default)." }}
{{- end }}
{{- if and .Values.trust.trustedKeysConfigMap (eq .Values.trust.trustedKeysConfigMap .Values.trust.acceptorKeysConfigMap) }}
{{- fail "trust.trustedKeysConfigMap and trust.acceptorKeysConfigMap name the same ConfigMap: one key may not both sign attestations and accept their gaps." }}
{{- end }}
{{- end }}
