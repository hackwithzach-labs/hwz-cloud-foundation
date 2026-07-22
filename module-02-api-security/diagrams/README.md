# Diagrams

Chapter 9's "Map it: the API on the foundation" section is the reference for this artifact.

`api-on-foundation-starter.drawio` extends the module-01 foundation diagram with the inference API placed as a layer on top. Open it in draw.io, then:

1. List the four controls inside the API container.
2. Draw and label the three real flows from the API down into the foundation: it assumes the least-privilege IAM role (identity), reads its credential from Secrets Manager (a secret), and reaches the model through the Bedrock endpoint in the private subnets (the model call).
3. Add one box to the controls strip: "API layer: audience-bound tokens, schema, per-token caps, structured audit."

Commit the `.drawio` source and a PNG exported at 200 percent zoom, and update the narration paragraph in your README to name the new layer. Foundation plus the API that stands on it is a stronger portfolio piece than either alone.

Drawing the API as a layer that sits on the foundation, rather than a separate picture, is the comprehension check: if you can show the three flows without looking back at the code, you understand how the API composes onto the ground you own.

(c) 2026 Vigilantia Technologies INC. All rights reserved.
