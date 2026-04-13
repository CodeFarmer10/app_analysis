import Java from 'frida-java-bridge';

const rules = globalThis.__frida_rules__ || [];

function safeToString(value) {
  try {
    if (value === null || value === undefined) {
      return null;
    }
    return String(value);
  } catch (_error) {
    return '<unprintable>';
  }
}

function isClassNotFoundError(error) {
  const message = safeToString(error) || '';
  return message.includes('ClassNotFoundException') || message.includes("Didn't find class");
}

function sendState(status, extra) {
  const payload = {
    type: 'state',
    status,
  };
  if (extra) {
    Object.keys(extra).forEach((key) => {
      payload[key] = extra[key];
    });
  }
  send(payload);
}

function installHooks() {
  sendState('script_loaded', { rule_count: rules.length });

  rules.forEach(function (rule) {
    try {
      let targetClass;
      try {
        targetClass = Java.use(rule.class_name);
      } catch (error) {
        if (isClassNotFoundError(error)) {
          sendState('class_missing', {
            rule_id: rule.id,
            class_name: rule.class_name,
          });
          return;
        }
        throw error;
      }
      if (!targetClass[rule.method_name]) {
        sendState('method_missing', { rule_id: rule.id });
        return;
      }
      const overloads = targetClass[rule.method_name].overloads || [];
      let boundCount = 0;

      overloads.forEach(function (overload) {
        try {
          const argTypes = overload.argumentTypes || [];
          if (rule.arg_count !== null && rule.arg_count !== undefined && argTypes.length !== rule.arg_count) {
            return;
          }
          const signature = argTypes
            .map(function (item) {
              return item.className || item.name || 'unknown';
            })
            .join(',');

          overload.implementation = function () {
            let argIndex = null;
            let args = null;
            if (rule.stringify_args) {
              const rawIndex = rule.hook_args;
              let targetIndex = 0;
              if (rawIndex !== null && rawIndex !== undefined) {
                const parsed = Number(rawIndex);
                if (Number.isFinite(parsed) && parsed >= 0) {
                  targetIndex = Math.floor(parsed);
                }
              }
              if (targetIndex >= 0 && targetIndex < arguments.length) {
                argIndex = targetIndex;
                args = safeToString(arguments[targetIndex]);
              }
            }

            const retval = overload.call.apply(
              overload,
              [this].concat(Array.prototype.slice.call(arguments))
            );
            send({
              type: 'event',
              payload: {
                rule_id: rule.id,
                class_name: rule.class_name,
                method_name: rule.method_name,
                signature,
                timestamp: Date.now() / 1000,
                arg_index: argIndex,
                args,
                retval: rule.include_retval && rule.stringify_retval ? safeToString(retval) : null,
              },
            });
            return retval;
          };
          boundCount += 1;
        } catch (hookError) {
          sendState('hook_error', {
            rule_id: rule.id,
            error: safeToString(hookError),
          });
        }
      });

      sendState('hooked', {
        rule_id: rule.id,
        overloads: boundCount,
      });
    } catch (error) {
      sendState('hook_error', {
        rule_id: rule.id,
        error: safeToString(error),
      });
    }
  });
}

function startJavaHooks() {
  try {
    Java.perform(function () {
      sendState('java_ready');
      installHooks();
    });
  } catch (error) {
    sendState('java_bridge_error', {
      error: safeToString(error),
    });
  }
}

setImmediate(startJavaHooks);
