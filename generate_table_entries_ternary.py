#!/usr/bin/env python3
import os
import sys
import pickle as pickle
import numpy as np
import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'
from sklearn import tree
import re
from netaddr import IPAddress
from statistics import mode
import random
import ipaddress
import warnings

warnings.filterwarnings("ignore", message="DataFrame is highly fragmented")
global priority
np.random.seed(42)

# ----------------------------
# Helper conversion functions
# ----------------------------
def bin_to_int(x):
    """
    Convert x (int or binary-like string) to integer.
    Accepts:
      - integer values (returns as is)
      - strings with '0b' prefix e.g. '0b10101'
      - strings with 'b' prefix e.g. 'b10101'
      - plain binary strings '10101'
    Raises ValueError for invalid characters.
    """
    if isinstance(x, int):
        return x
    x = str(x).strip()
    if x.startswith("0b"):
        x = x[2:]
    elif x.startswith("b"):
        x = x[1:]
    if x == '':
        raise ValueError("Empty binary literal encountered")
    if not all(ch in "01" for ch in x):
        raise ValueError(f"Invalid binary literal: {x}")
    return int(x, 2)

def safe_bin_to_int(x, log_on_error=False):
    """
    Defensive wrapper around bin_to_int:
    - returns 0 if x is empty or can't be parsed
    - tries to salvage by removing non-binary chars
    """
    try:
        return bin_to_int(x)
    except Exception:
        try:
            if x is None:
                if log_on_error:
                    print(f"safe_bin_to_int: None encountered, returning 0")
                return 0
            xs = str(x).strip()
            if xs == "":
                if log_on_error:
                    print(f"safe_bin_to_int: empty string encountered for value {x!r}, returning 0")
                return 0
            # Try to salvage by stripping non-binary characters
            cleaned = re.sub(r'[^01]', '', xs)
            if cleaned == "":
                if log_on_error:
                    print(f"safe_bin_to_int: could not salvage {x!r}, returning 0")
                return 0
            return int(cleaned, 2)
        except Exception:
            if log_on_error:
                print(f"safe_bin_to_int: unexpected error converting {x!r}, returning 0")
            return 0

def hex_of_bin(x):
    """Return hex() of a binary-like string or int."""
    return hex(bin_to_int(x))

# ----------------------------
# import and get entries from trained models
# ----------------------------
clf = pd.read_pickle('categorical_classification.pkl')

## list the feature names
feature_names = ['Min differential Packet Length', 'Min Packet Length', 'Max Packet Length', 'Flow Duration', 'IAT Range', 'Packet Length Range', 'First4Sum', 'Last4Sum']
split_ranges = {feature: [] for feature in feature_names}

## definition of useful functions
## gets all splits and conditions
def get_splits(forest, feature_names):
    data = []
    #generate dataframe with all thresholds and features
    for t in range(len(forest.estimators_)):
        clf_t = forest[t]
        n_nodes = clf_t.tree_.node_count
        features  = [feature_names[i] for i in clf_t.tree_.feature]
        for i in range(0, n_nodes):
            node_id = i
            left_child_id = clf_t.tree_.children_left[i]
            right_child_id = clf_t.tree_.children_right[i]
            threshold = clf_t.tree_.threshold[i]
            feature = features[i]
            if threshold != -2.0:
                data.append([t, node_id, left_child_id,
                             right_child_id, threshold, feature])
    data = pd.DataFrame(data)
    data.columns = ["Tree","NodeID","LeftID","RightID","Threshold","Feature"]
    return data

## gets the feature table of each feature from the splits
def get_feature_table(splits_data, feature_name):
    feature_data = splits_data[splits_data["Feature"]==feature_name]
    feature_data = feature_data.sort_values(by="Threshold").reset_index(drop=True)
    if feature_data.empty:
        # Return empty DataFrame with expected columns to avoid breakage downstream
        return pd.DataFrame(columns=["Threshold"])
    # convert thresholds
    feature_data["Threshold"] = feature_data["Threshold"].astype(int)
    code_table = pd.DataFrame()
    code_table["Threshold"] = feature_data["Threshold"]
    # create a column for each split in each tree
    for tree_id, node in zip(list(feature_data["Tree"]), list(feature_data["NodeID"])):
        colname = "s"+str(tree_id)+"_"+str(node)
        code_table[colname] = np.where(
            (code_table["Threshold"] <=
             feature_data[(feature_data["NodeID"]== node) & (feature_data["Tree"]==tree_id)]["Threshold"].values[0]),
            0, 1)
    # if code_table is empty (rare) handle gracefully
    if code_table.empty:
        return code_table
    # add a row to represent the values above the largest threshold
    temp = [max(code_table["Threshold"]) + 1]
    temp.extend([1] * (len(code_table.columns) - 1))
    code_table.loc[len(code_table)] = temp
    code_table = code_table.drop_duplicates(subset=['Threshold']).reset_index(drop=True)
    return code_table

## gets codes and masks
def get_codes_and_masks(clf_local, feature_names):
    # reusable functions below expect the same helpers as the rest of the script
    splits = get_order_of_splits(get_splits_per_tree(clf_local, feature_names), feature_names)
    codes = []
    masks = []

    for branch, coded in zip(list(retrieve_branches(clf_local)), get_leaf_paths(clf_local)):
        code = [0]*len(splits)
        mask = [0]*len(splits)
        for index, split in enumerate(splits):
            if split in branch:
                mask[index] = 1
        masks.append(mask)
        codes.append(code)

    masks = pd.DataFrame(masks) if masks else pd.DataFrame()
    if not masks.empty:
        masks['Mask'] = masks[masks.columns[0:]].apply(lambda x: ''.join(x.dropna().astype(str)),axis=1)
        masks = ["0b" + x for x in masks['Mask']]
    else:
        masks = []

    indices = range(0,len(splits))
    temp = pd.DataFrame(columns=["split", "index"], dtype=object)
    temp["split"] = splits
    temp["index"] = indices

    final_codes = []
    for branch, code, coded in zip(list(retrieve_branches(clf_local)), codes, get_leaf_paths(clf_local)):
        indices_to_use = temp[temp["split"].isin(branch)].sort_values(by="split")["index"]
        for i, j in zip(range(0,len(coded)), list(indices_to_use)):
            code[j] = coded[i]
        final_codes.append(code)

    final_codes = pd.DataFrame(final_codes) if final_codes else pd.DataFrame()
    if not final_codes.empty:
        final_codes["Code"] = final_codes[final_codes.columns[0:]].apply(lambda x: ''.join(x.dropna().astype(str)),axis=1)
        final_codes = ["0b" + x for x in final_codes["Code"]]
    else:
        final_codes = []
    return final_codes, masks

def split_20_bits(code_str):
    if len(code_str) <= 20:
        return [code_str]
    segments = [code_str[i:i + 20] for i in range(0, len(code_str), 20)]
    return segments

## get feature tables with ranges and codes only
def get_feature_codes_with_ranges(feature_table, num_of_trees):
    # guard for empty feature_table
    if feature_table is None or feature_table.empty:
        return pd.Series(dtype=object), pd.DataFrame()
    Codes = pd.DataFrame()
    for tree_id in range(num_of_trees):
        colname = "code"+str(tree_id)
        cols = [col for col in feature_table.columns if ('s'+str(tree_id)+'_') in col]
        if cols:
            Codes[colname] = feature_table[cols].apply(lambda x: ''.join(x.dropna().astype(str)),axis=1)
        else:
            # no splits for this tree & feature -> empty strings (preserve length)
            Codes[colname] = [''] * len(feature_table)
    # initialize Range as object dtype to avoid dtype coercion warnings
    feature_table["Range"] = [''] * len(feature_table)
    if len(feature_table) > 0:
        feature_table.loc[0, "Range"] = "0," + str(feature_table["Threshold"].loc[0])
    for i in range(1, len(feature_table)):
        if i == (len(feature_table)) - 1:
            feature_table.loc[i, "Range"] = str(feature_table["Threshold"].loc[i]) + "," + str(feature_table["Threshold"].loc[i])
        else:
            feature_table.loc[i, "Range"] = str(feature_table["Threshold"].loc[i-1] + 1) + "," + str(feature_table["Threshold"].loc[i])
    Ranges = feature_table["Range"]
    return Ranges, Codes

## get list of splits crossed to get to leaves
def retrieve_branches(estimator):
    number_nodes = estimator.tree_.node_count
    children_left_list = estimator.tree_.children_left
    children_right_list = estimator.tree_.children_right
    # Calculate if a node is a leaf
    is_leaves_list = [(False if cl != cr else True) for cl, cr in zip(children_left_list, children_right_list)]
    # Store the branches paths
    paths = []
    for i in range(number_nodes):
        if is_leaves_list[i]:
            end_node = [path[-1] for path in paths]
            if i in end_node:
                output = paths.pop(np.argwhere(i == np.array(end_node))[0][0])
                yield output
        else:
            origin, end_l, end_r = i, children_left_list[i], children_right_list[i]
            for index, path in enumerate(paths):
                if origin == path[-1]:
                    paths[index] = path + [end_l]
                    paths.append(path + [end_r])
            if i == 0:
                paths.append([i, children_left_list[i]])
                paths.append([i, children_right_list[i]])

## get classes and certainties
def get_classes(clf_local):
    leaves = []
    classes = []
    certainties = []
    for branch in list(retrieve_branches(clf_local)):
        leaves.append(branch[-1])
    for leaf in leaves:
        if clf_local.tree_.n_outputs == 1:
            value = clf_local.tree_.value[leaf][0]
        else:
            value = clf_local.tree_.value[leaf].T[0]
        class_name = np.argmax(value)
        certainty = int(round(max(value)/sum(value),2)*100)
        classes.append(class_name)
        certainties.append(certainty)
    return classes, certainties

## get the codes corresponging to the branches followed
def get_leaf_paths(clf_local):
    branch_codes = []
    for branch in list(retrieve_branches(clf_local)):
        code = [0]*len(branch)
        for i in range(1, len(branch)):
            if (branch[i] == clf_local.tree_.children_left[branch[i-1]]):
                code[i] = 0
            elif (branch[i] == clf_local.tree_.children_right[branch[i-1]]):
                code[i] = 1
        branch_codes.append(list(code[1:]))
    return branch_codes

## get the order of the splits to enable code generation
def get_order_of_splits(data, feature_names_local):
    splits_order = []
    for feature_name in feature_names_local:
        feature_data = data[data.iloc[:,4] == feature_name]
        feature_data = feature_data.sort_values(by="Threshold")
        for node in list(feature_data.iloc[:,0]):
            splits_order.append(node)
    return splits_order

def get_splits_per_tree(clf_local, feature_names_local):
    data = []
    n_nodes = clf_local.tree_.node_count
    features  = [feature_names_local[i] for i in clf_local.tree_.feature]
    for i in range(0, n_nodes):
        node_id = i
        left_child_id = clf_local.tree_.children_left[i]
        right_child_id = clf_local.tree_.children_right[i]
        threshold = clf_local.tree_.threshold[i]
        feature = features[i]
        if threshold != -2.0:
            data.append([node_id, left_child_id, right_child_id, threshold, feature])
    data = pd.DataFrame(data)
    data.columns = ["NodeID","LeftID","RightID","Threshold","Feature"]
    return data

## End of model manipulation ##

## Range to ternary conversion ##

def generate_last_exact_value(feature_index, end_value, hi_binary, codes):
    hi_int = bin_to_int(hi_binary)
    # Only add `(hi, hi)` if it was NOT already included**
    found_hi = any(end == hi_int for _, end, _ in split_ranges[feature_names[feature_index]])
    if not found_hi and bin_to_int(end_value) == hi_int - 1:
        mask = generate_mask(feature_index, hi_binary)
        split_ranges[feature_names[feature_index]].append(
            (hex(bin_to_int(hi_binary)), hex(bin_to_int(mask)), codes)
        )

def generate_end_value(modified_lo_binary):
    value_binary = ''
    for i in range(len(modified_lo_binary)):
        if modified_lo_binary[i] == 'x':
            value_binary += '1'
        else:
            value_binary += modified_lo_binary[i]
    return value_binary

def generate_start_value(modified_lo_binary):
    value_binary = ''
    for i in range(len(modified_lo_binary)):
        if modified_lo_binary[i] == 'x':
            value_binary += '0'
        else:
            value_binary += modified_lo_binary[i]
    return value_binary

def generate_mask(feature_index, modified_binary):
    mask_binary = ''
    for i in range(len(modified_binary)):
        if modified_binary[i] == 'x':
            mask_binary += '0'
        elif modified_binary[i] != 'x':
            mask_binary += '1'
    # Fix: ensure mask list entries are correct (added missing comma)
    if feature_names[feature_index] in [
        "IAT min",
        "Min differential Packet Length",
        "Max differential Packet Length",
        "IAT max"
    ]:
        mask_binary = '1' * (32 - len(mask_binary)) + mask_binary
    else:
        mask_binary = '1' * (16 - len(mask_binary)) + mask_binary
    return mask_binary

def handle_trailing_zeros(feature_index, trailing_zeros, lo_binary, hi_binary, codes):
    lo_binary_list = list(lo_binary)
    retain_length = len(lo_binary) - trailing_zeros
    lo_binary_list[retain_length:] = ['x'] * trailing_zeros
    modified_lo_binary = ''.join(lo_binary_list)
    mask = generate_mask(feature_index, modified_lo_binary)
    start_value = generate_start_value(modified_lo_binary)
    end_value = generate_end_value(modified_lo_binary)
    split_ranges[feature_names[feature_index]].append(
        (hex(bin_to_int(start_value)), hex(bin_to_int(mask)), codes)
    )
    generate_last_exact_value(feature_index, end_value, hi_binary, codes)

def lo_binary_ranges(feature_index, lo_binary, hi_binary, codes):
    lo_binary_list = list(lo_binary)
    lo_val = bin_to_int(lo_binary)
    hi_val = bin_to_int(hi_binary)
    # If lo + 1 == hi, add directly and return
    if lo_val + 1 == hi_val:
        if feature_names[feature_index] not in split_ranges:
            split_ranges[feature_names[feature_index]] = []
        differing_indices = [i for i in range(len(lo_binary)) if lo_binary[i] != hi_binary[i]]
        if len(differing_indices) == len(lo_binary):  # All bits differ
            for value in range(lo_val, hi_val + 1):
                mask = generate_mask(feature_index, hi_binary)
                split_ranges[feature_names[feature_index]].append(
                    (hex(value), hex(bin_to_int(mask)), codes)
                )
        else:
            modified_binary = list(lo_binary)
            modified_binary[-1] = 'x'
            modified_binary = ''.join(modified_binary)
            mask = generate_mask(feature_index, modified_binary)
            split_ranges[feature_names[feature_index]].append(
                (hex(bin_to_int(lo_binary)), hex(bin_to_int(mask)), codes)
            )
        return
    # If equal
    if lo_val == hi_val:
        if feature_names[feature_index] not in split_ranges:
            split_ranges[feature_names[feature_index]] = []
        mask = generate_mask(feature_index, hi_binary)
        split_ranges[feature_names[feature_index]].append(
            (hex(bin_to_int(lo_binary)), hex(bin_to_int(mask)), codes)
        )
        return
    # Find trailing zeros
    trailing_zeros = 0
    trailing_zeros_index = 0
    for index in range(0, len(lo_binary)):
        if hi_binary[index] > lo_binary[index]:
            trailing_zeros_index = index
            break
    for bit in reversed(lo_binary[trailing_zeros_index + 1:]):
        if bit == '0':
            trailing_zeros += 1
        else:
            break
    if trailing_zeros > 0:
        handle_trailing_zeros(feature_index, trailing_zeros, lo_binary, hi_binary, codes)
    first_one_found = False
    if trailing_zeros > 0:
        first_one_found = True
    for index in range(trailing_zeros + 1, len(lo_binary)):
        bit = lo_binary[-index]
        actual_position = index
        if bit == '1' and not first_one_found and bin_to_int(lo_binary) != bin_to_int(hi_binary) - 1:
            mask = generate_mask(feature_index, lo_binary)
            split_ranges[feature_names[feature_index]].append(
                (hex(bin_to_int(lo_binary)), hex(bin_to_int(mask)), codes)
            )
            first_one_found = True
        elif bit == '0' and first_one_found:
            lo_binary_list[-actual_position] = '1'
            lo_binary_list[-actual_position + 1:] = ['x'] * (actual_position - 1)
            modified_lo_binary = ''.join(lo_binary_list)
            end_value = generate_end_value(modified_lo_binary)
            if bin_to_int(end_value) < bin_to_int(hi_binary):
                mask = generate_mask(feature_index, modified_lo_binary)
                start_value = generate_start_value(modified_lo_binary)
                split_ranges[feature_names[feature_index]].append(
                    (hex(bin_to_int(start_value)), hex(bin_to_int(mask)), codes)
                )
                generate_last_exact_value(feature_index, end_value, hi_binary, codes)
            else:
                return index

def hi_binary_ranges(index, feature_index, hi_binary, lo_binary, lo, hi, codes):
    original_hi_binary_list = list(hi_binary)
    start_index = len(hi_binary) - index + 1
    if index == 0:
        start_index = 1
    if feature_names[feature_index] not in split_ranges:
        split_ranges[feature_names[feature_index]] = []
    last_processed_end = lo - 1
    for idx in range(start_index, len(original_hi_binary_list)):
        hi_binary_list = original_hi_binary_list[:]
        if hi_binary_list[idx] == '1':
            hi_binary_list[idx] = '0'
            if idx == len(original_hi_binary_list) - 1 and original_hi_binary_list[-1] == '1':
                hi_binary_list[-1] = 'x'
            else:
                hi_binary_list[idx+1:] = ['x'] * (len(hi_binary_list) - idx - 1)
            modified_hi_binary = ''.join(hi_binary_list)
            mask = generate_mask(feature_index, modified_hi_binary)
            start_value = generate_start_value(modified_hi_binary)
            end_value = generate_end_value(modified_hi_binary)
            if lo <= bin_to_int(end_value) <= hi:
                split_ranges[feature_names[feature_index]].append(
                    (hex(bin_to_int(start_value)), hex(bin_to_int(mask)), codes)
                )
                last_processed_end = bin_to_int(end_value)
    if last_processed_end < hi:
        mask = generate_mask(feature_index, hi_binary)
        split_ranges[feature_names[feature_index]].append(
            (hex(bin_to_int(hi_binary)), hex(bin_to_int(mask)), codes)
        )

def generate_ternary_ranges(lo, hi, i, codes):
    lo_binary = bin(lo)[2:]
    hi_binary = bin(hi)[2:]
    max_length = max(len(lo_binary), len(hi_binary))
    lo_binary = lo_binary.zfill(max_length)
    hi_binary = hi_binary.zfill(max_length)
    get_hi_binary_start_index = lo_binary_ranges(i, lo_binary, hi_binary, codes)
    if lo != hi and lo + 1 != hi:
        if get_hi_binary_start_index is not None:
            hi_binary_ranges(get_hi_binary_start_index, i, hi_binary, lo_binary, lo, hi, codes)
        else:
            hi_binary_ranges(0, i, hi_binary, lo_binary, lo, hi, codes)

## End of Range to ternary conversion ##

# Generate rules
for fea in range(0, len(feature_names)):
    Ranges, Codes = get_feature_codes_with_ranges(get_feature_table(get_splits(clf, feature_names), feature_names[fea]), len(clf.estimators_))
    # If empty skip
    if Codes is None or (isinstance(Codes, pd.DataFrame) and Codes.empty):
        print(f"WARNING: No codes generated for feature {feature_names[fea]} — skipping.")
        continue
    column_names = Codes.columns.tolist()
    for ran, *code_segments in zip(Ranges, Codes.itertuples(index=False, name=None)):
        if ran == Ranges.iloc[len(Ranges)-1]:
            if feature_names[fea] in ["Min differential Packet Length", "Min Packet Length", "Max Packet Length", "IAT min", "IAT max"]:
                lo = int(str(ran.split(",")[0]))
                hi = 4294967295
            else:
                lo = int(str(ran.split(",")[0]))
                hi = 65535
        else:
            lo = int(str(ran.split(",")[0]))
            hi = int(str(ran.split(",")[1]))
        code_segments_list = [item for sublist in code_segments for item in sublist]
        column_value_pairs = list(zip(column_names, code_segments_list))
        generate_ternary_ranges(lo, hi, fea, column_value_pairs)

for fea in range(0, len(feature_names)):
    print(feature_names[fea])
    with open(f"rules_{feature_names[fea].replace(' ', '_').lower()}.txt", "w") as entries_file:
        priority = 0
        for combination in split_ranges[feature_names[fea]]:
            priority += 1
            value, mask, codes = combination
            values = [f"{value}/{mask}"]
            formatted_values = " ".join(values)
            action_params = []
            for index, action in enumerate(codes):
                param, val = action

                # Defensive normalization: treat empty/None as zero.
                if val is None:
                    int_val = 0
                else:
                    vstr = str(val).strip()
                    if vstr == "":
                        int_val = 0
                    else:
                        # Try normal conversion, then salvage on failure
                        try:
                            int_val = bin_to_int(vstr)
                        except ValueError:
                            cleaned = re.sub(r'[^01]', '', vstr)
                            if cleaned == "":
                                int_val = 0
                            else:
                                int_val = int(cleaned, 2)

                action_params.append(f"{param} {hex(int_val)}")
            rule = f"match {formatted_values} priority {priority} action SetCode{fea} " + " ".join(action_params)
            print(rule, file=entries_file)

for tree_id in range(0, len(clf.estimators_)):
    priority = 0
    with open(f"rules_code_table{str(tree_id)}.txt", "w") as entries_file:
        Final_Codes, Final_Masks = get_codes_and_masks(clf.estimators_[tree_id], feature_names)
        Classe, Certain = get_classes(clf.estimators_[tree_id])
        if not Final_Codes:
            continue
        for cod, mas, cla, cer in zip(Final_Codes, Final_Masks, Classe, Certain):
            priority += 1
            # Use safe conversion to avoid empty binary strings causing crashes
            cod_int = safe_bin_to_int(cod)
            mas_int = safe_bin_to_int(mas)
            rule = f"match {hex(cod_int)}/{hex(mas_int)} priority {priority} action SetClass{tree_id} class {cla + 1}"
            print(rule, file=entries_file)

with open(f"rules_voting_table.txt", "w") as entries_file:
    priority = 0
    for i in range(1, 3):
        for j in range(1, 3):
            for k in range(1, 3):
                try:
                    priority += 1
                    choices = [i, j, k]
                    mode_number = mode(choices)
                    print("match "+  str(i) + " " + str(j) + " " + str(k) + " priority {}".format(priority)+" action set_final_class" + " class_result " + str(mode_number), file=entries_file)
                except:
                    pass

print("** TABLE ENTRIES GENERATED AND STORED IN DESIGNATED FILE **")