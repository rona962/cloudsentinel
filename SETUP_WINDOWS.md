# CloudSentinel — Setup Guide (Windows)

## 1. Instalar AWS CLI v2

Abre PowerShell como Administrador:

```powershell
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```

O descarga el instalador desde: https://awscli.amazonaws.com/AWSCLIV2.msi

Verifica:
```powershell
aws --version
```

## 2. Instalar AWS SAM CLI

Descarga el instalador MSI desde:
https://github.com/aws/aws-sam-cli/releases/latest

O con winget:
```powershell
winget install Amazon.SAM-CLI
```

Verifica:
```powershell
sam --version
```

## 3. Configurar tu cuenta personal

```powershell
aws configure --profile personal
```

Te va a pedir:
- **AWS Access Key ID**: (la generas en IAM > Users > tu usuario > Security credentials)
- **AWS Secret Access Key**: (se muestra solo una vez al crearla)
- **Default region**: us-east-1
- **Default output format**: json

## 4. Setear el perfil por defecto para este proyecto

```powershell
$env:AWS_PROFILE = "personal"
```

O para que sea permanente en tu sesión de PowerShell, agrega esto a tu `$PROFILE`:
```powershell
$env:AWS_PROFILE = "personal"
```

## 5. Verificar que funciona

```powershell
aws sts get-caller-identity --profile personal
```

Deberías ver tu Account ID, ARN y User ID.

## 6. Instalar Docker Desktop (necesario para SAM local)

Descarga desde: https://www.docker.com/products/docker-desktop/

SAM usa Docker para simular Lambda localmente. No es obligatorio para deploy, pero útil para testing.

## 7. Clonar/crear el proyecto

```powershell
mkdir C:\Projects\cloudsentinel
cd C:\Projects\cloudsentinel
```

Copia ahí los archivos del proyecto que te voy a generar.

## 8. Deploy del Sprint 1

```powershell
cd C:\Projects\cloudsentinel
sam build
sam deploy --guided --profile personal
```

La primera vez `--guided` te pregunta configuración (stack name, region, etc). Después usa `sam deploy` solo.

---

## Costos esperados: ~$0/mes

Los servicios usados están dentro del Free Tier:
- Lambda: 1M requests gratis/mes
- DynamoDB: 25GB + 25 RCU/WCU gratis
- S3: 5GB gratis primer año
- EventBridge: Gratis para reglas custom
- CloudTrail: 1 trail gratis
- SNS: 1M publicaciones gratis
- Step Functions: 4,000 transiciones gratis/mes
- CloudWatch: 10 custom metrics gratis
