defmodule Core.Validation.Binding do
  @moduledoc """
  Host-owned authority for invoking one validation action by subject reference.

  Agent and RPC transports should pass inert identifiers, not executable
  validator options. A binding keeps the resolver, scope policy, scan plan,
  target function, and other current authority on the host side. It is
  intentionally not serializable and must be rebuilt when a session resumes.

  This is the transport-neutral seam used by adapters such as Lemieux tools:
  the adapter accepts only a `subject_type` and `subject_id`, resolves the
  current subject through the binding, and receives an ordinary
  `Core.Validation.Result`.
  """

  alias Core.Validation
  alias Core.Validation.{Action, Request, Result}

  @type subject_type :: Action.subject_type()
  @type resolver :: (subject_type(), String.t() ->
                       {:ok, Request.subject()} | {:error, term()})

  @type t :: %__MODULE__{
          validator: module(),
          action: Action.t(),
          resolver: resolver(),
          validator_options: keyword(),
          request_context: map(),
          request_meta: map()
        }

  @enforce_keys [:validator, :action, :resolver]
  defstruct [
    :validator,
    :action,
    :resolver,
    validator_options: [],
    request_context: %{},
    request_meta: %{}
  ]

  @doc "Builds a current-authority binding for exactly one advertised action."
  @spec new!(validator :: module(), action_id :: String.t(), opts :: keyword()) :: t()
  def new!(validator, action_id, opts)
      when is_atom(validator) and is_binary(action_id) and is_list(opts) do
    opts =
      Keyword.validate!(opts,
        resolver: nil,
        validator_options: [],
        request_context: %{},
        request_meta: %{}
      )

    resolver = Keyword.fetch!(opts, :resolver)
    validator_options = Keyword.fetch!(opts, :validator_options)
    request_context = Keyword.fetch!(opts, :request_context)
    request_meta = Keyword.fetch!(opts, :request_meta)

    unless is_function(resolver, 2) and Keyword.keyword?(validator_options) and
             is_map(request_context) and is_map(request_meta) do
      raise ArgumentError,
            "binding requires a two-argument resolver, keyword validator options, and map context/metadata"
    end

    action =
      validator
      |> Validation.actions()
      |> Enum.find(&(&1.id == action_id))

    unless action do
      raise ArgumentError,
            "#{inspect(validator)} does not advertise validation action #{inspect(action_id)}"
    end

    %__MODULE__{
      validator: validator,
      action: action,
      resolver: resolver,
      validator_options: validator_options,
      request_context: request_context,
      request_meta: request_meta
    }
  end

  @doc "Invokes the bound action from a string- or atom-keyed subject reference."
  @spec invoke(binding :: t(), reference :: map()) :: {:ok, Result.t()} | {:error, term()}
  def invoke(%__MODULE__{} = binding, reference) when is_map(reference) do
    with {:ok, type, id} <- parse_reference(reference),
         :ok <- accepts(binding.action, type),
         {:ok, subject} <- resolve(binding, type, id),
         :ok <- matching_subject(subject, type, id) do
      request =
        Validation.request(binding.action, subject,
          context: binding.request_context,
          meta: binding.request_meta
        )

      {:ok, Validation.run(binding.validator, request, binding.validator_options)}
    end
  end

  def invoke(%__MODULE__{}, reference), do: {:error, {:invalid_subject_reference, reference}}

  defp parse_reference(reference) do
    allowed = ["subject_type", "subject_id", :subject_type, :subject_id]

    unknown =
      reference
      |> Map.keys()
      |> Enum.reject(&(&1 in allowed))
      |> Enum.sort_by(&inspect/1)

    if unknown == [] do
      parse_reference_values(
        Map.get(reference, "subject_type", Map.get(reference, :subject_type)),
        Map.get(reference, "subject_id", Map.get(reference, :subject_id))
      )
    else
      {:error, {:unknown_subject_reference_fields, unknown}}
    end
  end

  defp parse_reference_values(type, id) when is_binary(id) and byte_size(id) > 0 do
    case type do
      "finding" -> {:ok, :finding, id}
      :finding -> {:ok, :finding, id}
      "seed" -> {:ok, :seed, id}
      :seed -> {:ok, :seed, id}
      "hypothesis" -> {:ok, :hypothesis, id}
      :hypothesis -> {:ok, :hypothesis, id}
      _other -> {:error, {:invalid_subject_type, type}}
    end
  end

  defp parse_reference_values(_type, id), do: {:error, {:invalid_subject_id, id}}

  defp accepts(%Action{accepts: accepts}, type) do
    if type in accepts,
      do: :ok,
      else: {:error, {:unsupported_subject_type, type}}
  end

  defp resolve(binding, type, id) do
    case binding.resolver.(type, id) do
      {:ok, subject} -> {:ok, subject}
      {:error, reason} -> {:error, {:subject_unavailable, reason}}
      other -> {:error, {:invalid_resolver_result, other}}
    end
  end

  defp matching_subject(%Core.Finding{id: id}, :finding, id), do: :ok
  defp matching_subject(%Core.Seed{id: id}, :seed, id), do: :ok
  defp matching_subject(%Core.Hypothesis{id: id}, :hypothesis, id), do: :ok

  defp matching_subject(subject, type, id),
    do: {:error, {:resolved_subject_mismatch, type, id, subject}}
end
