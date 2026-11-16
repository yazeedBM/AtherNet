// The visual AND/OR filter builder.
//
// The design proposal asks for this by name, and the reason is the audience:
// a query language is faster for someone who already knows one and a wall for
// everyone else. This is dropdowns, with the filter written back as a
// sentence underneath so nobody has to guess what they have built.
//
// Two levels. Conditions inside a group combine one way, groups combine the
// other, which gives "(A or B) and C" without ever showing a bracket to
// someone who did not ask for one.

import { useState } from 'react';
import {
  conditionCount,
  deleteSaved,
  describe,
  EMPTY_BUILDER,
  FIELDS,
  fieldSpec,
  isEmpty,
  loadSaved,
  newCondition,
  newGroup,
  OP_LABEL,
  saveFilter,
  SHORTCUTS,
  type Condition,
  type FieldId,
  type Filter,
  type OpId,
  type SavedFilter,
} from './filter';

export function FilterBuilder({
  filter,
  onChange,
}: {
  filter: Filter;
  onChange: (filter: Filter) => void;
}) {
  const [saved, setSaved] = useState<SavedFilter[]>(() => loadSaved());
  const [name, setName] = useState('');

  function editGroup(key: string, change: (g: Filter['groups'][number]) => Filter['groups'][number]) {
    onChange({
      ...filter,
      groups: filter.groups.map((g) => (g.key === key ? change(g) : g)),
    });
  }

  function editCondition(groupKey: string, conditionKey: string, change: Partial<Condition>) {
    editGroup(groupKey, (g) => ({
      ...g,
      conditions: g.conditions.map((c) => (c.key === conditionKey ? { ...c, ...change } : c)),
    }));
  }

  return (
    <div className="builder">
      <div className="builder-shortcuts">
        <span className="muted">Start from</span>
        {SHORTCUTS.map((shortcut) => (
          <button
            type="button"
            key={shortcut.name}
            className="chip"
            title={shortcut.hint}
            onClick={() => onChange(shortcut.build())}
          >
            {shortcut.name}
          </button>
        ))}
      </div>

      {filter.groups.length === 0 && (
        <p className="muted empty-note">
          No filter yet. Pick one above, or build one: every packet has to match what you add here.
        </p>
      )}

      {filter.groups.map((group, groupIndex) => (
        <div className="builder-group" key={group.key}>
          {groupIndex > 0 && (
            <div className="joiner">
              <button
                type="button"
                className="chip is-on"
                onClick={() => onChange({ ...filter, matchAll: !filter.matchAll })}
                title="Switch how these groups combine"
              >
                {filter.matchAll ? 'AND' : 'OR'}
              </button>
            </div>
          )}

          <div className="builder-group-head">
            <label>
              Match
              <select
                value={group.matchAll ? 'all' : 'any'}
                onChange={(e) => editGroup(group.key, (g) => ({ ...g, matchAll: e.target.value === 'all' }))}
              >
                <option value="all">all of these</option>
                <option value="any">any of these</option>
              </select>
            </label>
            <button
              type="button"
              className="rail-close"
              aria-label="Remove this group"
              onClick={() =>
                onChange({ ...filter, groups: filter.groups.filter((g) => g.key !== group.key) })
              }
            >
              ×
            </button>
          </div>

          {group.conditions.map((condition) => (
            <ConditionRow
              key={condition.key}
              condition={condition}
              onChange={(change) => editCondition(group.key, condition.key, change)}
              onRemove={() =>
                editGroup(group.key, (g) => ({
                  ...g,
                  conditions: g.conditions.filter((c) => c.key !== condition.key),
                }))
              }
            />
          ))}

          <button
            type="button"
            className="linklike"
            onClick={() => editGroup(group.key, (g) => ({ ...g, conditions: [...g.conditions, newCondition()] }))}
          >
            + condition
          </button>
        </div>
      ))}

      <div className="builder-actions">
        <button
          type="button"
          className="open-button ghost"
          onClick={() => onChange({ ...filter, groups: [...filter.groups, newGroup()] })}
        >
          + group
        </button>
        {!isEmpty(filter) && (
          <button type="button" className="open-button ghost" onClick={() => onChange(EMPTY_BUILDER)}>
            Clear
          </button>
        )}
      </div>

      <p className="builder-sentence">
        <strong>Showing:</strong> {describe(filter)}
      </p>

      <div className="builder-save">
        <input
          className="search small"
          placeholder="Name this filter to keep it"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button
          type="button"
          className="open-button"
          disabled={!name.trim() || isEmpty(filter)}
          onClick={() => {
            setSaved(saveFilter(name.trim(), filter));
            setName('');
          }}
        >
          Save
        </button>
      </div>

      {saved.length > 0 && (
        <div className="builder-saved">
          <span className="muted">Saved</span>
          {saved.map((entry) => (
            <span className="saved-chip" key={entry.name}>
              <button
                type="button"
                className="chip"
                title={describe(entry.filter)}
                onClick={() => onChange(entry.filter)}
              >
                {entry.name} · {conditionCount(entry.filter)}
              </button>
              <button
                type="button"
                className="rail-close"
                aria-label={`Forget the saved filter ${entry.name}`}
                onClick={() => setSaved(deleteSaved(entry.name))}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}

      <p className="muted builder-note">
        Saved filters stay in this browser. There is no account and no server to keep them on, and a filter
        is a question about your own network.
      </p>
    </div>
  );
}

function ConditionRow({
  condition,
  onChange,
  onRemove,
}: {
  condition: Condition;
  onChange: (change: Partial<Condition>) => void;
  onRemove: () => void;
}) {
  const spec = fieldSpec(condition.field);
  return (
    <div className="condition">
      <select
        value={condition.field}
        aria-label="What to match on"
        onChange={(e) => {
          const field = e.target.value as FieldId;
          const next = fieldSpec(field);
          // The old operator may not apply to the new field, and the old
          // value almost never does.
          onChange({ field, op: next.ops[0], value: '' });
        }}
      >
        {FIELDS.map((f) => (
          <option key={f.id} value={f.id}>
            {f.label}
          </option>
        ))}
      </select>

      <button
        type="button"
        className={`chip tiny ${condition.negate ? 'is-on' : ''}`}
        aria-pressed={condition.negate}
        title="Match everything except this"
        onClick={() => onChange({ negate: !condition.negate })}
      >
        not
      </button>

      <select
        value={condition.op}
        aria-label="How to compare"
        onChange={(e) => onChange({ op: e.target.value as OpId })}
      >
        {spec.ops.map((op) => (
          <option key={op} value={op}>
            {OP_LABEL[op]}
          </option>
        ))}
      </select>

      {spec.choices ? (
        <select
          value={condition.value}
          aria-label="Value"
          onChange={(e) => onChange({ value: e.target.value })}
        >
          <option value="">choose…</option>
          {spec.choices.map((choice) => (
            <option key={choice} value={choice}>
              {choice}
            </option>
          ))}
        </select>
      ) : (
        <input
          className="search small"
          value={condition.value}
          placeholder={spec.placeholder}
          aria-label="Value"
          onChange={(e) => onChange({ value: e.target.value })}
        />
      )}

      <button type="button" className="rail-close" aria-label="Remove this condition" onClick={onRemove}>
        ×
      </button>

      {spec.hint && <span className="condition-hint muted">{spec.hint}</span>}
    </div>
  );
}
