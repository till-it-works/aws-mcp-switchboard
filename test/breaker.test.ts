import { beforeEach, describe, expect, it, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { LambdaClient, PutFunctionConcurrencyCommand } from "@aws-sdk/client-lambda";
import type { SNSEvent } from "aws-lambda";
import { createBreaker } from "../lambda/breaker.js";

const lambdaMock = mockClient(LambdaClient);
const sns = (msg: object | string): SNSEvent =>
  ({ Records: [{ Sns: { Message: typeof msg === "string" ? msg : JSON.stringify(msg) } }] }) as unknown as SNSEvent;
const trip = createBreaker({ lambda: new LambdaClient({}), target: "sb-handler" });

beforeEach(() => {
  lambdaMock.reset();
  vi.spyOn(console, "log").mockImplementation(() => {});
});

describe("breaker", () => {
  it("ALARM → reserved concurrency 0 on the target (stops all invocations until reset)", async () => {
    await trip(sns({ AlarmName: "invocations", NewStateValue: "ALARM" }));
    expect(lambdaMock.commandCalls(PutFunctionConcurrencyCommand).map((c) => c.args[0].input)).toEqual([
      { FunctionName: "sb-handler", ReservedConcurrentExecutions: 0 },
    ]);
  });

  it.each([{ NewStateValue: "OK" }, { NewStateValue: "INSUFFICIENT_DATA" }, "not json"])("ignores %j", async (m) => {
    await trip(sns(m));
    expect(lambdaMock.commandCalls(PutFunctionConcurrencyCommand)).toHaveLength(0);
  });

  it("fails loudly when the target cannot be throttled (SNS retries)", async () => {
    lambdaMock.on(PutFunctionConcurrencyCommand).rejects(new Error("AccessDenied"));
    await expect(trip(sns({ NewStateValue: "ALARM" }))).rejects.toThrow("AccessDenied");
  });
});
