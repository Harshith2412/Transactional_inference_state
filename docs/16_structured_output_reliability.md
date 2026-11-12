# Structured-output reliability

The trusted parser was unchanged between prompting configurations.

| Model | Prompt | Parse success | Benign completion | Model compromise |
|---|---|---:|---:|---:|
| llama3.2:3b | strict JSON | 11.56% | 1.01% | 1% |
| llama3.2:3b | explicit schema | 96% | 100% | 92% |
| qwen3:4b | strict JSON | 0% | 0% | 0% |
| qwen3:4b | explicit schema | 0% | 0% | 0% |

On the Llama explicit-schema subset, baseline persistent compromise was 92%,
transactional persistent compromise 0%, and containment given compromise 100%.
Higher format reliability enabled legitimate plans but also exposed the model's
willingness to follow malicious instructions. Parse success is therefore a
utility/boundary-reliability metric, not a security metric by itself.

Failure summaries distinguish malformed output, unknown operation, missing or
extra fields, invalid type, duplicate ID, and other parser failures. Qwen's
tested outputs all failed parsing under both prompts. That result is local and
prompt/version-specific.

See [structured summary](../evaluation_results/structured_output/summary.csv)
and [Figure 5](../evaluation_results/figures/figure_05_structured_output.svg).
