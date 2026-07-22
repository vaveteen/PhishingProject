# Hartnell Security 411 — AWS Lambda Deployment Guide

## Architecture Overview

```
┌─────────────────────────────────┐     ┌────────────────────────┐     ┌─────────────────────────────────┐
│  S3: hartnell-security411-source│     │     AWS Lambda         │     │  S3: hartnell-security411-drafts│
│                                 │────▶│  lambda_function.py    │────▶│                                 │
│  training_set.csv               │     │                        │     │  newsletter_2026-07.txt         │
└─────────────────────────────────┘     └────────────────────────┘     └─────────────────────────────────┘
                                               ▲
                                               │ Monthly trigger
                                        ┌──────┴───────┐
                                        │  EventBridge  │
                                        │  (Schedule)   │
                                        └──────────────┘
```

## Prerequisites

- AWS account with access to Lambda, S3, IAM, and EventBridge
- S3 buckets already created:
  - `hartnell-security411-source` (us-west-2)
  - `hartnell-security411-drafts` (us-west-2)
- `training_set.csv` uploaded to the source bucket

## Step 1: Create the IAM Role

The Lambda function needs permission to read from the source bucket and write to the drafts bucket.

### Option A: AWS Console

1. Go to **IAM → Roles → Create role**
2. Select **AWS service → Lambda**
3. Click **Next: Permissions**
4. Click **Create policy** and paste the JSON from `iam_policy.json` (below)
5. Name it: `hartnell-security411-lambda-policy`
6. Attach it to the role
7. Also attach: `AWSLambdaBasicExecutionRole` (for CloudWatch logs)
8. Name the role: `hartnell-security411-lambda-role`

### Option B: AWS CLI

```bash
# Create the role
aws iam create-role \
  --role-name hartnell-security411-lambda-role \
  --assume-role-policy-document file://trust_policy.json

# Attach the custom policy
aws iam put-role-policy \
  --role-name hartnell-security411-lambda-role \
  --policy-name hartnell-security411-s3-access \
  --policy-document file://iam_policy.json

# Attach CloudWatch Logs permission
aws iam attach-role-policy \
  --role-name hartnell-security411-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

## Step 2: Create the Lambda Function

### Option A: AWS Console (Easiest)

1. Go to **Lambda → Create function**
2. Choose **Author from scratch**
3. Settings:
   - **Function name:** `hartnell-security411-newsletter`
   - **Runtime:** Python 3.11
   - **Architecture:** x86_64
   - **Execution role:** Use existing role → `hartnell-security411-lambda-role`
4. Click **Create function**
5. In the code editor, **delete** the default code
6. **Copy-paste** the entire contents of `lambda_function.py`
7. Click **Deploy**

### Configuration (Important!)

After creating the function:

1. Go to **Configuration → General configuration → Edit**
   - **Memory:** 512 MB (increase to 1024 MB for datasets >20k emails)
   - **Timeout:** 5 minutes (300 seconds)
   - Click **Save**

2. Go to **Configuration → Environment variables → Edit**
   - Add these variables:

   | Key | Value |
   |-----|-------|
   | `SOURCE_BUCKET` | `hartnell-security411-source` |
   | `DRAFTS_BUCKET` | `hartnell-security411-drafts` |
   | `SOURCE_KEY` | `training_set.csv` |
   | `SIMILARITY_THRESHOLD` | `0.90` |

### Option B: AWS CLI

```bash
# Zip the function
zip lambda_package.zip lambda_function.py

# Create the function
aws lambda create-function \
  --function-name hartnell-security411-newsletter \
  --runtime python3.11 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/hartnell-security411-lambda-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda_package.zip \
  --timeout 300 \
  --memory-size 512 \
  --region us-west-2 \
  --environment Variables="{SOURCE_BUCKET=hartnell-security411-source,DRAFTS_BUCKET=hartnell-security411-drafts,SOURCE_KEY=training_set.csv,SIMILARITY_THRESHOLD=0.90}"
```

## Step 3: Set Up Monthly Schedule (EventBridge)

### AWS Console

1. Go to **Amazon EventBridge → Rules → Create rule**
2. Settings:
   - **Name:** `hartnell-security411-monthly`
   - **Event bus:** default
   - **Rule type:** Schedule
3. Schedule pattern:
   - **Schedule expression:** `cron(0 9 1 * ? *)` 
   - (This runs at 9:00 AM UTC on the 1st of every month)
4. Target:
   - **Target type:** AWS service → Lambda function
   - **Function:** `hartnell-security411-newsletter`
5. Click **Create**

### AWS CLI

```bash
# Create the rule
aws events put-rule \
  --name hartnell-security411-monthly \
  --schedule-expression "cron(0 9 1 * ? *)" \
  --region us-west-2

# Add Lambda as target
aws events put-targets \
  --rule hartnell-security411-monthly \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-west-2:YOUR_ACCOUNT_ID:function:hartnell-security411-newsletter" \
  --region us-west-2

# Grant EventBridge permission to invoke Lambda
aws lambda add-permission \
  --function-name hartnell-security411-newsletter \
  --statement-id hartnell-monthly-trigger \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-west-2:YOUR_ACCOUNT_ID:rule/hartnell-security411-monthly \
  --region us-west-2
```

## Step 4: Test the Function

### Manual Test in Console

1. Go to **Lambda → hartnell-security411-newsletter → Test**
2. Create a test event with any JSON (the function ignores event content):
   ```json
   {
     "source": "manual-test"
   }
   ```
3. Click **Test**
4. Check the output and CloudWatch logs
5. Verify the newsletter file appeared in `hartnell-security411-drafts`

### Verify Output

1. Go to **S3 → hartnell-security411-drafts**
2. You should see a file like `newsletter_2026-07.txt`
3. Download and review the draft before distribution

## Step 5: Upload Your Training Set

Make sure `training_set.csv` is in the source bucket:

```bash
aws s3 cp training_set.csv s3://hartnell-security411-source/training_set.csv
```

Or upload via the S3 Console:
1. Go to **S3 → hartnell-security411-source**
2. Click **Upload**
3. Add `training_set.csv`
4. Click **Upload**

---

## Local Testing (No AWS Required)

You can test the newsletter generation locally without AWS:

```bash
python lambda_function.py training_set.csv
```

This will:
- Read the CSV from your local filesystem
- Run the full duplicate detection analysis
- Print the newsletter to the console
- Save it to `newsletter_YYYY-MM.txt` in the current directory

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Timeout` error | Increase timeout to 300s or 600s in Lambda config |
| `Memory` error | Increase memory to 1024 MB or 2048 MB |
| `Access Denied` on S3 | Check IAM policy is attached to the Lambda role |
| No newsletter generated | Verify `training_set.csv` exists in source bucket |
| Empty newsletter (no alerts) | Check that CSV has PHISHING emails with duplicates |

---

## Cost Estimate

- **Lambda:** ~$0.01/month (runs once, ~30 seconds for 20k emails)
- **S3:** ~$0.01/month (small text files)
- **EventBridge:** Free tier covers monthly schedule
- **Total:** Essentially free under AWS free tier

---

## Future Enhancements

- **SES Integration:** If a domain is set up with Route 53, the Lambda can send the newsletter directly via SES instead of writing to S3
- **SNS Notification:** Add an SNS topic to notify an admin when a new draft is ready for review
- **Multiple datasets:** Modify SOURCE_KEY to process multiple CSV files per run
