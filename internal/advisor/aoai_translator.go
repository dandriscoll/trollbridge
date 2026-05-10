package advisor

import (
	"encoding/json"
	"fmt"
)

// aoaiTranslator speaks the Azure OpenAI chat-completions API
// (https://learn.microsoft.com/en-us/azure/ai-services/openai/reference).
// The deployment is part of the URL path (operator-supplied via
// llm.endpoint); the body's `model` field is informational and
// echoed back by the service. We force a single function tool_call
// to the trollbridge_decision function so the model's reply always
// carries a structured advisor decision.
//
// Auth: api-key (NOT Authorization: Bearer). The header name is
// the one Azure OpenAI's data plane accepts.
type aoaiTranslator struct{}

// aoaiMaxTokens caps the assistant response. Same reasoning as
// the Anthropic side — the model only needs to emit one tool_call.
const aoaiMaxTokens = 1024

func (aoaiTranslator) Name() string { return "aoai" }

type aoaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aoaiFunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type aoaiToolDef struct {
	Type     string          `json:"type"` // always "function"
	Function aoaiFunctionDef `json:"function"`
}

type aoaiToolChoiceFunction struct {
	Name string `json:"name"`
}

type aoaiToolChoice struct {
	Type     string                 `json:"type"` // always "function"
	Function aoaiToolChoiceFunction `json:"function"`
}

type aoaiRequest struct {
	Model      string          `json:"model,omitempty"`
	Messages   []aoaiMessage   `json:"messages"`
	MaxTokens  int             `json:"max_tokens,omitempty"`
	Tools      []aoaiToolDef   `json:"tools,omitempty"`
	ToolChoice *aoaiToolChoice `json:"tool_choice,omitempty"`
}

func (aoaiTranslator) BuildRequest(in Input, model, apiKey string) ([]byte, map[string]string, error) {
	serialized, err := json.Marshal(in)
	if err != nil {
		return nil, nil, fmt.Errorf("aoai: marshal input: %w", err)
	}
	messages := []aoaiMessage{
		{Role: "system", Content: composeSystemPrompt(in.Mode, in.Directives)},
		{Role: "user", Content: userPrompt(serialized)},
	}

	req := aoaiRequest{
		Model:     model, // empty is fine — deployment in URL path dictates the model
		Messages:  messages,
		MaxTokens: aoaiMaxTokens,
		Tools: []aoaiToolDef{{
			Type: "function",
			Function: aoaiFunctionDef{
				Name:        toolName,
				Description: toolDescription,
				Parameters:  decisionSchema(),
			},
		}},
		ToolChoice: &aoaiToolChoice{
			Type:     "function",
			Function: aoaiToolChoiceFunction{Name: toolName},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("aoai: marshal request: %w", err)
	}
	hdr := map[string]string{
		"Content-Type": "application/json",
	}
	if apiKey != "" {
		hdr["api-key"] = apiKey
	}
	return body, hdr, nil
}

type aoaiToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type aoaiToolCall struct {
	ID       string               `json:"id"`
	Type     string               `json:"type"`
	Function aoaiToolCallFunction `json:"function"`
}

type aoaiChoiceMessage struct {
	Role      string         `json:"role"`
	Content   string         `json:"content"`
	ToolCalls []aoaiToolCall `json:"tool_calls,omitempty"`
}

type aoaiChoice struct {
	Index        int               `json:"index"`
	Message      aoaiChoiceMessage `json:"message"`
	FinishReason string            `json:"finish_reason"`
}

type aoaiResponse struct {
	Choices []aoaiChoice `json:"choices"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (aoaiTranslator) ParseResponse(httpStatus int, body []byte) (Output, error) {
	if httpStatus < 200 || httpStatus >= 300 {
		return Output{}, fmt.Errorf("%w: aoai http %d: %s",
			ErrAdvisorWire, httpStatus, truncateForLog(string(body), 256))
	}
	var resp aoaiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Output{}, fmt.Errorf("%w: aoai decode: %v: %s",
			ErrAdvisorSchema, err, truncateForLog(string(body), 256))
	}
	if resp.Error != nil {
		return Output{}, fmt.Errorf("%w: aoai api error: %s: %s",
			ErrAdvisorSchema, resp.Error.Code, resp.Error.Message)
	}
	if len(resp.Choices) == 0 {
		return Output{}, fmt.Errorf("%w: aoai response had no choices", ErrAdvisorSchema)
	}
	msg := resp.Choices[0].Message
	if len(msg.ToolCalls) == 0 {
		return Output{}, fmt.Errorf("%w: aoai response had no tool_calls (finish_reason=%q); model returned text instead of invoking the %s function: %s",
			ErrAdvisorSchema, resp.Choices[0].FinishReason, toolName, truncateForLog(msg.Content, 256))
	}
	for _, tc := range msg.ToolCalls {
		if tc.Function.Name != toolName {
			continue
		}
		var out Output
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &out); err != nil {
			return Output{}, fmt.Errorf("%w: aoai tool_call arguments decode: %v: %s",
				ErrAdvisorSchema, err, truncateForLog(tc.Function.Arguments, 256))
		}
		return out, nil
	}
	return Output{}, fmt.Errorf("%w: aoai response tool_calls did not include %q",
		ErrAdvisorSchema, toolName)
}
