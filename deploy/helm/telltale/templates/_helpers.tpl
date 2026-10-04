{{- define "telltale.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "telltale.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "telltale.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "telltale.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "telltale.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "telltale.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "telltale.selectorLabels" -}}
app.kubernetes.io/name: {{ include "telltale.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: all
{{- end }}

{{/* The DNS port inside the pod: 53 on the host network, else dnsPort. */}}
{{- define "telltale.dnsPort" -}}
{{- if .Values.hostNetwork }}53{{ else }}{{ .Values.dnsPort }}{{ end }}
{{- end }}
