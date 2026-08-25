{{- define "silo.fullname" -}}
{{- .Release.Name }}-silo
{{- end -}}

{{- define "silo.labels" -}}
app.kubernetes.io/name: silo
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "silo.configSecretName" -}}
{{- if .Values.existingConfigSecret -}}
{{ .Values.existingConfigSecret }}
{{- else -}}
{{ include "silo.fullname" . }}-config
{{- end -}}
{{- end -}}
