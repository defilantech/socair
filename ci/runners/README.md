# Self-hosted CI runners

While the defilantech repositories are private, CI runs on self-hosted runners
on the homelab microk8s cluster to save GitHub Actions minutes. They use
Actions Runner Controller (ARC) runner scale sets; the controller is the
existing `arc` release in `arc-systems`.

| File | What |
|---|---|
| `Dockerfile` | The runner image: the official `actions-runner` plus `build-essential` (for `go test -race`) and Chrome's system libraries (for socair-web's pa11y test) |
| `build-job.yaml` | Builds the image inside the cluster with kaniko and pushes it to the microk8s registry (`localhost:32000`) |
| `values.yaml` | The org-level scale set `defilantech-runners`: 0 to 3 runners, on demand |

## Setup

1. **Create a GitHub App** owned by defilantech:
   - Organization permission **Self-hosted runners: Read and write**; Repository permission **Metadata: Read-only**.
   - Webhook inactive.
   - Install it on the repositories that use these runners.
2. **Store its credentials:**
   ```
   kubectl --context microk8s -n arc-runners create secret generic defilantech-runners-github-app \
     --from-literal=github_app_id=<APP_ID> \
     --from-literal=github_app_installation_id=<INSTALLATION_ID> \
     --from-file=github_app_private_key=<key.pem>
   ```
3. **Build the image:** see the comment at the top of `build-job.yaml`.
4. **Install the scale set:** see the comment at the top of `values.yaml`.
5. **Use it in workflows:** `runs-on: defilantech-runners`.

`release.yml` stays on GitHub-hosted runners: it runs rarely, and its
reproducible-build check compares against GitHub's machines.

## When a repository goes public

Switch its workflows back to `runs-on: ubuntu-latest`:
- public repositories get GitHub-hosted minutes free;
- a self-hosted runner on a public repository would run code from outside
  pull requests on the homelab.

The org's Default runner group does not serve public repositories, so until
`runs-on` is switched, a public repo's jobs would simply wait in the queue.

## Updating

To move to a new runner release:
1. Bump the `FROM` tag in `Dockerfile`, and the image tag in `build-job.yaml` and `values.yaml` together.
2. Rebuild the image.
3. Run `helm upgrade` with the same values.
