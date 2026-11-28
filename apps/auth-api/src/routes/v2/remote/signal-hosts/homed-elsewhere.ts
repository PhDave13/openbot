import { createFileRoute } from "@tanstack/solid-router";
import { Effect } from "effect";
import { z } from "zod";
import { runApiResponse } from "../../../../server/effect-runtime";
import { readRequestBytes } from "../../../../server/json-body";
import { REMOTE_SIGNAL_HOSTS_BATCH_LIMIT } from "../../../../server/remote-control-plane";
import {
  apiError,
  json,
  remoteControlPlaneErrorResponse,
  requestRemoteControlPlane,
  verifyRemoteServiceRequest,
} from "../../../../server/request-auth";

const SIGNAL_HOSTS_BODY_LIMIT = 64 * 1024;

const signalHostsSchema = z.object({
  signal: z.string().regex(/^[a-z0-9-]{1,32}$/),
  hostIds: z.array(z.string().min(1).max(256)).min(1).max(REMOTE_SIGNAL_HOSTS_BATCH_LIMIT),
});

export const Route = createFileRoute("/v2/remote/signal-hosts/homed-elsewhere")({
  server: {
    handlers: {
      POST: ({ request }) =>
        runApiResponse(
          Effect.gen(function* () {
            const body = new TextDecoder().decode(yield* readRequestBytes(request, SIGNAL_HOSTS_BODY_LIMIT));
            if (!(yield* verifyRemoteServiceRequest(request, body))) {
              return apiError(401, "invalid_signature", "The Remote service signature is invalid.");
            }
            let parsed: ReturnType<typeof signalHostsSchema.safeParse>;
            try {
              parsed = signalHostsSchema.safeParse(JSON.parse(body));
            } catch {
              return apiError(400, "invalid_signal_hosts", "The Signal host list is invalid.");
            }
            if (!parsed.success) return apiError(400, "invalid_signal_hosts", "The Signal host list is invalid.");
            return json({
              hostIds: yield* requestRemoteControlPlane().signalHostsHomedElsewhere(
                parsed.data.signal,
                parsed.data.hostIds,
              ),
            });
          }),
          remoteControlPlaneErrorResponse,
        ),
    },
  },
});
