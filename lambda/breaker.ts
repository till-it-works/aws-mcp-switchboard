/**
 * Cost breaker: subscribed to the invocation alarm's SNS topic. On ALARM it sets the switchboard's
 * reserved concurrency to 0, which stops every invocation until an operator runs `npm run breaker:reset`.
 */
import { LambdaClient, PutFunctionConcurrencyCommand } from "@aws-sdk/client-lambda";
import type { SNSEvent } from "aws-lambda";

export function createBreaker(deps: { lambda: LambdaClient; target: string }) {
  return async (event: SNSEvent): Promise<void> => {
    for (const r of event.Records) {
      let msg: { AlarmName?: string; NewStateValue?: string };
      try {
        msg = JSON.parse(r.Sns.Message) as typeof msg;
      } catch {
        continue;
      }
      if (msg.NewStateValue !== "ALARM") continue;
      await deps.lambda.send(new PutFunctionConcurrencyCommand({ FunctionName: deps.target, ReservedConcurrentExecutions: 0 }));
      console.log(JSON.stringify({ msg: "breaker_tripped", target: deps.target, alarm: msg.AlarmName }));
    }
  };
}

export const handler = createBreaker({ lambda: new LambdaClient({}), target: process.env.TARGET_FUNCTION_NAME ?? "" });
